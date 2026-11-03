# Network Forensics

Network forensics for home and small networks: find out what a device on your LAN is
talking to, write it down, then lock it down and prove the lockdown works.

## Skills

- `lockdown-iot-device`: keep an IoT device (IP camera, smart plug, hub) local-only.
  Observes in three windows (idle, live remote view on mobile data, reboot for DNS
  names and the firmware check), monitors DNS from the capture and checks payloads
  for cleartext IDs, audio and video.
  Probe the hardware (OUI, ports, ONVIF, web UI, RTSP), capture and trace its cloud
  egress at the firewall (state table, packet capture, whois, DNS/SNI from the pcap),
  document the findings, apply block rules (incl. IPv6, UPnP, hard-coded DNS), kill
  live states and verify. Router specifics are for OPNsense (API calls in
  `references/opnsense-api.md`); the method applies to any stateful firewall.

- `verify-iot-lockdown`: apply the block and record what happens afterwards. Covers
  the rule set, killing states, a test matrix at 10 min, 1 h and 24 h (RTSP, ONVIF,
  NVR recording continuity, clock drift, vendor app on the LAN and off it), what the
  device keeps trying (firewall log by destination and rate), and a reboot while
  blocked. Writes `post-block.md`.
- `score-device-security`: rates a device on the 100-point Local-Only Security Rubric
  (`references/rubric.md`). Local-only viability (does it work cut off?) and cloud
  exposure (cleartext media, cleartext IDs, hard-coded DNS/IPs, cloud sprawl, weak
  services, CVEs). Statuses carry evidence levels (tested / documented / inferred),
  red flags cap the grade, and untested criteria keep the score provisional with a
  ceiling. Computed by `scripts/score.py` from one JSON file per device.

The playbook comes from a real investigation: a Xiongmai-firmware Wi-Fi PTZ camera that
the vendor app could reach from anywhere, with no port-forward. It was holding UDP P2P
keep-alives and TCP relay sessions to Huawei Cloud and using hard-coded public DNS, so
DNS filtering alone could not stop it.

## Requirements

`nmap`, `tshark` (Wireshark CLI), `whois`, `curl`, `jq`, `ffprobe`; `uv` for the
optional ONVIF query. For OPNsense via API: `OPNSENSE_URL`, `OPNSENSE_KEY`,
`OPNSENSE_SECRET` in the environment.

## Installation

```bash
claude plugins marketplace add danielrosehill/Claude-Code-Plugins
claude plugins install network-forensics@danielrosehill
```

## Licence

MIT
