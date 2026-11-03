---
name: lockdown-iot-device
description: Lock an IoT device (IP camera, smart plug) to the LAN - probe it, capture and trace its cloud egress at the firewall, document, block, verify.
---

# Lock an IoT device to the LAN

Forensics-first playbook for a device the user wants to keep using **locally only**
(e.g. a cheap IP camera feeding Frigate, Home Assistant or an NVR) while cutting its
vendor cloud. Worked out on a Xiongmai-firmware Wi-Fi PTZ camera behind OPNsense; the
method carries to any device and any stateful firewall.

**Order is the point: probe, observe and document before you block.** Once the rule
is in, the interesting traffic stops and can no longer be studied.

## Inputs

- **Device**: its current IP or MAC, and what it is used for locally (RTSP to an NVR,
  ONVIF, a local API). Ask if unknown.
- **Router**: type and how to reach it. OPNsense is covered in detail
  (`references/opnsense-api.md`, key/secret in `OPNSENSE_URL`, `OPNSENSE_KEY`,
  `OPNSENSE_SECRET`); for other routers, use their state table, packet capture and
  rule UI with the same steps.
- **Where to record it**: a repo or folder for the dossier. Default: a repo named for
  the subject (e.g. `IP-Cam-Lockdown`) with `devices/`, `forensics/`, `captures/`
  (git-ignored) and a `playbook.md`. Ask once whether it will be public; if so, apply
  the redaction rules below from the first commit.
- **Local credentials** for the device, if the user has them.

## Phase 1: Pin and probe the hardware

1. **DHCP reservation** by MAC, so every later rule keys on a stable IP. Note whether
   the device has a wired MAC too (often a placeholder like `00:12:34:...`).
2. **Get local access working** (RTSP/ONVIF login). Vendor apps often change the
   device password silently on pairing; if an NVR login now returns `401`, that is the
   usual cause.
3. **Identify the platform**, recording for each fact *how* it was obtained:
   - MAC OUI (`nmap -sn`, or the router's ARP table): usually the Wi-Fi chip vendor,
     not the device maker.
   - Port scan: `nmap -sT -p 1-10000 <dev>` plus targeted UDP
     (`sudo nmap -sU -p 53,123,1900,3702,5353,6668,8765,32100,32108 <dev>`). Match
     against `references/fingerprints.md`.
   - ONVIF `GetDeviceInformation`, `GetScopes`, `GetNetworkInterfaces`, `GetDNS`,
     `GetNTP` (snippet in `references/probing.md`). Model strings name the SoC;
     firmware strings identify the firmware house.
   - Web UI: fetch `/` and its JS; grep for hostnames (`curl -s http://<dev>/ | grep -oE
     '[a-z0-9.-]+\.(com|cn|net)'`). Plug-in download URLs often name the cloud brand.
   - Media: `ffprobe rtsp://<user>:<pw>@<dev>:554/<path>` for codec and real
     resolution. Compare with the listing's claims (an "8MP" listing streaming
     2880x1616 is the 5MP variant).
   - Purchase channel: store, listing URL, variant, price, date.
   - Companion app: name, and Android package ID (from the Play Store link, or
     `adb shell pm list packages` with the phone plugged in). Listings often show other
     products' apps; take the app from the box or the user.
4. Write `devices/<platform>-<model>.md` from `templates/device-dossier.md`.

## Phase 2: Observe its egress (before blocking)

Observe in **three windows**, each with its own capture, because each shows things the
others miss: **idle** (what it does on its own), **live remote view** (how the app
reaches it) and **reboot** (the names it resolves and what it calls at startup).
Nothing is blocked during this phase, so the app keeps working; tell the user that up
front, or "it still works in the app" reads as a failed block.

### Capture setup (all windows)

- Capture on the LAN-side interface (before NAT), device traffic only. Keep the filter
  **simple**: a plain `host <dev>`, excluding the NVR's local pull by port (e.g. not
  554). On OPNsense the capture `host` field silently rejects compound expressions such
  as `<dev> and not net <lan>`: the job runs but writes an empty pcap (24-byte header).
- **Check the pcap is growing within the first minute** (`search_jobs` size, or a quick
  `tcpdump -r cap.pcap -c 5`). Don't find out it was empty after the user's test.
- Alongside the capture, **snapshot the state table every ~20 s** during the active
  windows. Short-lived relay hops show up there even when the capture misses them.
- Note the wall-clock time of every user action, so bursts can be matched later.

### Window 1: idle

State table snapshot, then a 15-30 minute capture with nobody using the app. Answers:
which hosts it keeps sessions with, keep-alive interval, whether video or audio leaves
the house when nobody is watching.

### Window 2: live remote view

The user puts the phone **on mobile data (Wi-Fi off)**, opens the vendor app, watches
live for 1-2 minutes, moves PTZ, tries talk-back, then closes the app and says "done".
Answers: the session broker, whether a P2P hole-punch is attempted and whether it gets
a reply, which relays carry the stream (often several in turn, in different regions),
bitrate, and whether the media is encrypted (see payload inspection below).

### Window 3: reboot (DNS and startup)

Idle and live captures usually contain **no DNS at all**: the device resolved its
servers long ago and caches them. A capture across a power cycle gets them.

1. Start the capture, then have the user unplug the device, wait 10 s, plug it back
   in, and say when it is back in the NVR or app (about 2-3 minutes; the device is off
   for about one).
2. Read from it:
   - **DNS names**: cheap devices often ask a hard-coded public resolver in plain UDP
     53, so every name is visible. Names outlive IPs, so they are the most reusable
     finding: others with the same device can match or block them.
   - **Firmware-update check**: often plain HTTP at startup, exposing the update
     server and how the device reports its version.
   - **Startup order**: DHCP, NTP, DNS, cloud sign-in, then the keep-alives.
3. It may cache names or skip the update check; say so if the reboot adds nothing.

### Monitor DNS

The device may bypass the LAN resolver, so the LAN DNS logs show nothing; read DNS from
the captures:

```bash
tshark -r cap.pcap -Y 'dns.flags.response==0' -T fields -e frame.time_relative -e ip.dst -e dns.qry.name
tshark -r cap.pcap -Y 'dns.flags.response==1' -T fields -e dns.qry.name -e dns.a | sort -u   # name -> IPs
tshark -r cap.pcap -Y 'udp.port==53 && !(ip.dst==<router>)' -T fields -e ip.dst | sort | uniq -c   # resolvers it uses
```

Join `dns.a` against the flow table so each remote IP gets its name. Also check DoH/DoT
(TCP 853, or 443 to a known resolver IP): that hides names even from a capture.

### Attribute and read the traffic

```bash
whois <ip> | grep -iE 'netname|orgname|descr|country|route'
tshark -r cap.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u
tshark -r cap.pcap -q -z conv,udp -z conv,tcp      # who, how much, how long
tshark -r cap.pcap -q -z io,stat,10                # traffic per 10 s, to match user actions
tshark -r cap.pcap -Y 'http.request' -T fields -e ip.dst -e http.host -e http.request.uri   # plain HTTP (firmware checks)
```

Record the hosting owner *and* the role of each flow. Patterns (more in
`references/fingerprints.md`): long-lived bidirectional UDP to one host = registration
keep-alive / NAT pinhole; a persistent TCP session = control channel; one unanswered UDP
datagram when the app opens = failed P2P hole-punch; large outbound TCP lining up with
viewing = relayed stream; direct UDP 53 to a public resolver = hard-coded DNS; ICMP to
8.8.8.8 / 114.114.114.114 = "am I online" checks.

### Payload inspection

Check whether what leaves the house is encrypted, without decoding anything further
than needed:

```bash
tshark -r cap.pcap -Y 'ip.dst==<peer>' -T fields -e data.data | head        # keep-alive bytes
tshark -r cap.pcap -q -z follow,tcp,raw,<stream#> | xxd | head -40           # relay stream
strings -n 8 cap.pcap | sort | uniq -c | sort -rn | head                     # plaintext IDs, hosts
```

Look for the device serial / cloud ID in plain ASCII in keep-alives, vendor media frame
headers followed by codec start codes (plain video/audio), and A-law/µ-law silence runs
(`0x55`/`0xD5`, `0xFF`/`0x7F`) that mark raw audio. Count frame types to see which parts,
if any, are scrambled. Report what was seen, and mark decoding as not tested.

## Phase 3: Document

Write `forensics/<YYYY-MM-DD>-<model>/findings.md` from `templates/findings.md`
**before** touching the firewall:

- Method per window (idle, live view, reboot): exact commands/API calls, interface,
  filter, duration, what the user did and when. One file per window is fine
  (`findings.md`, `capture.md`, `reboot.md`).
- A flow table: proto, destination, name (from DNS), port, state, owner (whois), reading.
- Session sequence for the live view (broker, hole-punch, relays) and the boot order.
- What is in the clear (IDs, audio, video) and what is not.
- What it means in plain terms (e.g. "not reachable on the LAN but visible in the
  app" = both sides dial out to a broker; no port-forward is involved).
- **Confirmed vs assumed** on every claim. Mark inferences *assumed*.
- Open questions to close from the capture.

Raw captures stay out of the repo (`captures/` git-ignored): they carry the device's
cloud ID. Commit only extracts.

**Redaction for a public record**: serials or UIDs that double as the cloud/P2P ID,
credentials, full MACs (keep the OUI), the home's public IP, internal hostnames and
addressing beyond placeholders like `<cam>` and `<lan>`.

## Phase 4: Remediate

Confirm the rule set with the user before applying it. On the device's interface, at
the **top** of the rule list, in this order:

| # | Action | Source | Destination | Why |
|---|---|---|---|---|
| 1 | Pass | device | LAN net | replies to the NVR, ONVIF discovery |
| 2 | Pass | device | firewall, UDP 123 | NTP; point the device's NTP at the router or timestamps drift |
| 3 | Pass (optional) | device | firewall, 53 | local DNS only; omit to make it fully dark |
| 4 | **Block + log** | device | any | cloud, hard-coded DNS, ICMP checks, firmware calls |

Also:
- **IPv6**: block the device's v6 too (MAC-based alias, or no v6 on its VLAN), or it
  walks round a v4-only rule.
- **UPnP / NAT-PMP**: off, or deny the device. P2P stacks request port maps.
- **Device settings**: set NTP to the router; switch off cloud/P2P/remote access in
  the UI if offered. Treat this as cosmetic; the firewall is the control.
- Longer term: an IoT VLAN with no default route to WAN, only the NVR allowed in.

On OPNsense, back up the config first; rules can be added by API (see references).

## Phase 5: Verify

1. **Kill the device's existing states.** Established sessions survive a new rule
   until killed; without this the "block" appears not to work.
2. After ~10 minutes: the state table shows only LAN flows; the firewall log shows
   rule-4 blocks (that log is now the ongoing record of what it tries, and its retry
   rate).
3. Local use still works (NVR streams, ONVIF responds); the vendor app no longer
   connects off-LAN (test on mobile data).
4. Append the result, the date and the rule IDs/descriptions to `findings.md`, and
   update the device's status in the repo README.

## Phase 6: Keep it that way

- Firmware updates normally come from the cloud, so they stop. Check the vendor site
  for a manual image only for a known fix.
- Re-verify after router changes: new VLAN, IPv6 enablement, rule reorder, firmware
  upgrade.
- For the next device of the same family, reuse the dossier and diff its egress
  against the earlier findings.

## References

- `references/opnsense-api.md`: state table, packet capture, states kill, rules via API.
- `references/probing.md`: ONVIF queries, RTSP probe, web-UI hostname grep.
- `references/fingerprints.md`: ports and strings that identify common camera/IoT platforms.
- `templates/device-dossier.md`, `templates/findings.md`.
