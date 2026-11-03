---
name: verify-iot-lockdown
description: Apply and validate an internet block on an IoT device (IP camera), then record what happened afterwards. Does RTSP/ONVIF/NVR recording keep working, does the vendor app work on the LAN, what does the device keep trying to reach, does it survive a reboot while blocked? Tested at 10 min, 1 h and 24 h.
---

# Verify an IoT lockdown: what happens after the block

The remediation and validation half of `lockdown-iot-device` (which covers probing,
capture and documentation). It ends with a dated `post-block.md` for the device, which
settles the rubric criteria that need a block to test (L1, L2, L4, L5, L7 in
`score-device-security`).

**Precondition:** the device's egress has been captured and documented *before* this
(`lockdown-iot-device` Phases 1-3). Once the block is in, that traffic is gone.

## Inputs

- Device IP (DHCP-reserved), local credentials, the RTSP URL and the ONVIF port.
- The NVR (Frigate, Home Assistant, other) and how to check its recordings.
- Router access. OPNsense via API: `OPNSENSE_URL`, `OPNSENSE_KEY`, `OPNSENSE_SECRET`
  (calls in `../lockdown-iot-device/references/opnsense-api.md`). Other routers use the
  same steps in their UI.
- The repo/folder holding the device's forensics.

## Step 1: Baseline (just before the block)

Record each of these in `post-block.md` under "Baseline". They are the comparison for
every later check.

```bash
ffprobe -v error -rtsp_transport tcp -show_entries stream=codec_name,width,height -of csv \
  "rtsp://$USER:$PW@$DEV:554/<path>"                             # stream answers
date -u; curl -s -H 'Content-Type: application/soap+xml' "http://$DEV:<onvif-port>/onvif/device_service" -d \
 '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' \
 | grep -oE '<tt:(Hour|Minute|Second)>[0-9]+' | head -3            # device clock vs router clock
```

Plus: a state-table snapshot (all flows), the vendor app on the LAN (works?), the vendor
app on mobile data (works?), and the NVR's last recording segment time.

## Step 2: Apply the block (confirm first)

Show the user the exact rule set and get a yes. It changes the router, and the vendor app
stops working off the LAN. Then:

1. Back up the router config.
2. Rules, at the top, in order: pass device→LAN, pass device→router UDP 123 (NTP),
   optional pass device→router 53, **block + log device→any**. Same for IPv6 if the LAN
   has it. UPnP/NAT-PMP denied for the device.
3. Point the device's NTP at the router if it allows it (ONVIF `SetNTP`, web UI or app).
   Record whether it accepts an IP or only a hostname.
4. **Kill the device's existing states.** Established sessions survive a new rule; this
   is the most common reason a block "doesn't work".
5. Record: time (absolute, with zone), rule descriptions/UUIDs, states killed.

## Step 3: Test matrix at T+10 min, T+1 h, T+24 h

Run each check at each checkpoint, using a `/loop` or scheduled wake-ups for the later
ones. Record pass/fail with the exact output line.

| Check | How | Expected |
|---|---|---|
| RTSP stream | `ffprobe` as in the baseline | Same codec and resolution |
| ONVIF | `GetSystemDateAndTime` (and an authenticated `GetDeviceInformation`) | Answers |
| NVR recording | NVR UI/API: segments continuous since the block, no gaps | No gap beyond normal |
| Clock | Device time vs router time | Drift < 2 s at 24 h (with local NTP) |
| State table | Flows for the device | LAN and router only |
| Firewall log | Blocked attempts by destination and port, per hour | The ongoing record of what it tries |
| Vendor app, LAN | User opens the app on home Wi-Fi | Record exactly what works: live view, playback, settings, PTZ, talk-back |
| Vendor app, off-LAN | User on mobile data | Fails to connect (that is success) |

```bash
# blocked attempts per destination:port over the log window
api "diagnostics/firewall/log?limit=2000" | jq -r --arg d "$DEV" \
  '.[] | select(.src==$d and .action=="block") | "\(.dst):\(.dstport // "-") \(.protoname // .proto)"' \
  | sort | uniq -c | sort -rn | head -20
# retry rate: blocked packets per minute
api "diagnostics/firewall/log?limit=2000" | jq -r --arg d "$DEV" \
  '.[] | select(.src==$d and .action=="block") | .__timestamp__[0:16]' | uniq -c | tail -10
```

Compare the blocked destinations with the pre-block findings. **New destinations** (a
fallback server, DNS-over-HTTPS, a different hard-coded resolver) are findings in their
own right: whois them and add them to the flow table.

## Step 4: Reboot while blocked (once, after T+1 h)

Power-cycle the device with the block in place, and capture across it (`host $DEV`,
RTSP excluded; see the reboot window in `lockdown-iot-device`). Answers:

- Does it come back and stream to the NVR with no internet? (The decisive L1 test. Some
  firmware waits on a cloud or NTP check before starting services.)
- What does it try at boot when everything fails: fallback resolvers, fallback IPs,
  ICMP checks, how fast it retries?
- Does the clock come back right (no RTC + no NTP = 1970 timestamps)?

## Step 5: Record and re-score

Write `forensics/<YYYY-MM-DD>-<model>/post-block.md` from `templates/post-block.md`:
baseline, rules, the matrix at each checkpoint, the blocked-attempts table, the reboot
result, and anything that broke (feature lockout, nag, reboot loop, time drift). Mark
each claim tested or assumed.

Then:
1. Update the device's score file (`score-device-security`): L1, L2, L4, L5, L7 move from
   `unknown` (or `documented`) to `tested`. Re-run the scorer and update the published
   tables.
2. Update the device's status in the repo README ("blocked YYYY-MM-DD; local-only
   verified at 24 h").
3. Commit and push.

## If it fails

- **Stream stops after the block:** check the state kill took, then whether the device
  needs DNS (allow device→router 53) or NTP. Re-test one change at a time and record
  which one restored it. A device that only streams with a cloud path open is an L1
  `fail`. Say so plainly; that is the most important finding for anyone buying it.
- **The app still works off-LAN:** a state survived, IPv6 is open, or the rule is below
  an allow rule. Check in that order.
- **A traffic storm in the log:** record the rate. It is an L7 finding. Rate-limit or
  keep the rule without logging, but keep a sample.
