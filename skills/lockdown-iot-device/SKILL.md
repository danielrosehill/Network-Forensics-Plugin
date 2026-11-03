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
4. Write `devices/<platform>-<model>.md` from `templates/device-dossier.md`.

## Phase 2: Observe its egress (before blocking)

1. **State-table snapshot** for the device IP: every live flow, its peer, port, state
   and NAT translation. This is the fastest way to see the cloud path. OPNsense:
   Firewall → Diagnostics → States, or `query_states` (see references).
2. **Packet capture** of device↔internet only, on the LAN-side interface, filter
   `host <dev> and not net <lan-cidr>`, snaplen 1500, 30–60 minutes. While it runs,
   have the user exercise the cloud path: open the vendor app **on mobile data, not
   Wi-Fi**, view live, move PTZ, trigger a motion alert, then close the app. Note the
   times of each action so bursts can be matched later. Also capture a quiet period
   with nobody watching (does video leave the house unprompted?).
3. **Attribute every remote IP**: `whois <ip> | grep -iE 'netname|orgname|descr|country|route'`.
   Cloud-hosted vendors show up as Huawei Cloud, Alibaba, Tencent, AWS; record the
   hosting owner *and* what the flow appears to be.
4. **Pull names out of the capture** (the device may bypass the LAN resolver, so LAN
   DNS logs show nothing):
   ```bash
   tshark -r cap.pcap -Y dns.flags.response==0 -T fields -e ip.dst -e dns.qry.name | sort | uniq -c
   tshark -r cap.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u
   tshark -r cap.pcap -q -z conv,udp -z conv,tcp      # who, how much, how long
   tshark -r cap.pcap -q -z io,stat,60                 # traffic per minute, for bursts
   ```
5. **Read the pattern**, not just the list: long-lived bidirectional UDP to one host =
   P2P keep-alive / NAT pinhole; a persistent TCP session = control/relay channel;
   short TCP to the same host on other ports = status/report channels; direct UDP 53
   to a public resolver = hard-coded DNS; ICMP echo to 8.8.8.8 / 114.114.114.114 =
   "am I online" checks. Large outbound bursts that line up with app viewing = the
   stream is relayed through the cloud.

## Phase 3: Document

Write `forensics/<YYYY-MM-DD>-<model>/findings.md` from `templates/findings.md`
**before** touching the firewall:

- Method (exact commands/API calls, interface, filter, duration, what the user did
  and when).
- A flow table: proto, destination, port, state, owner (whois), reading.
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
