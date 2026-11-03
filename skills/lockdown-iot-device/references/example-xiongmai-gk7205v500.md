# Worked example: Xiongmai GK7205V500 Wi-Fi PTZ camera (2026-11-03)

One full run of this skill, summarised. The full public record (dossier, idle state
table, live-view capture, boot capture) is
<https://github.com/danielrosehill/IP-Cam-Lockdown>. IPs are as seen that day and will
change; names and ports are the durable part.

**Device:** AliExpress "8MP 4K IP Camera WiFi" (TPTEK Official Store), model string
`IPC_GK7205V500_G5S-WQ`, Xiongmai firmware on a Goke GK7205V500 SoC, AltoBeam Wi-Fi
(OUI `4C:2F:7B`). App: IPCee. Streams HEVC 2880x1616 (the 5MP variant, not the 8MP
advertised). LAN ports: 80, 554, 8899 (ONVIF), 34567 (XM DVRIP), UDP 3702, 8765, 32100;
LAN discovery on UDP 34569.

**Symptom that started it:** the NVR lost the camera while the app still showed it.
The camera had not moved; the NVR's login was getting `401` because the app had changed
the password. The app reached it through the cloud, with no port-forward.

## Idle

- UDP 8765 keep-alive every ~13 s to Huawei Cloud SG (and Akamai/Linode); 33-byte
  datagrams carrying the **serial / cloud ID in plain ASCII**.
- Persistent TCP 6510 control session to Huawei Cloud, plus short 6502/6615 sessions.
- One HTTPS session (~117 KB) to `pub-cfg.secu100.net` (Alibaba Cloud).
- DNS straight to 1.1.1.1; ICMP checks to 8.8.8.8 and 114.114.114.114.
- No video leaves when nobody watches.

## Live view (phone on mobile data)

1. TCP 8386 to an Alibaba Cloud host: relay broker.
2. One UDP datagram to Huawei Cloud HK :30000, no reply: failed P2P hole-punch.
3. Stream over **TCP 6611 through UCloud relays** (MY, SG, HK in turn), ~240 kbit/s.
4. Payload is Xiongmai's own framing, not TLS: **G.711 A-law audio in the clear**,
   HEVC P-frames in the clear, only I-frames look scrambled. Decoding not tested.

## Boot (power cycle)

- Only three DNS names, all to 1.1.1.1: `secu100.net` (7 Huawei Cloud A records,
  then TCP 8186), `pub-cfg.secu100.net` (TLS 443), `caps.secu100.net` (UDP 7999).
- Everything else by **hard-coded IP**: the 6510/6502/6615 control hosts, the 8765
  keep-alive hosts, the 30000 P2P host, the 8386 broker.
- Order: ICMP 114.114.114.114 → DNS → TCP 8186 → broker 8386 → WS-Discovery → NTP
  (`time.windows.com`) → UDP 7999 → ICMP 8.8.8.8 → TLS `pub-cfg` → 6615 + 8765
  keep-alives → 6510 control.
- No plaintext HTTP, so no visible firmware-update check.

## Conclusions that generalise

- "Offline on the LAN but live in the app" is usually a credentials or NVR problem plus
  a cloud relay, not a missing device.
- Blocking the vendor domain in DNS fails twice over: the device ignores the LAN
  resolver, and most endpoints are dialled by IP. Block by source at the firewall.
- Cheap cameras may send room audio unencrypted to third-party relays.

## Trap hit

The OPNsense capture `host` field accepted `<cam> and not <lan>/24` but wrote an
empty pcap. Plain host plus `port_not` 554 worked.
