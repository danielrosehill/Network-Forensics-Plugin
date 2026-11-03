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
