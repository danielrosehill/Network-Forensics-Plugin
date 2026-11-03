# Fingerprints for common camera / IoT platforms

Starting points, not proof. Record which signal you matched.

| Signal | Suggests |
|---|---|
| 34567/tcp (DVRIP / NetSurveillance) | Xiongmai (XM, JF Tech) firmware; XMEye / iCSee apps |
| Firmware string `V5.xx.Rxx...` | Xiongmai |
| Web UI references `jftechws.com`, `xmeye.net`, `xmcsrv.net` | Xiongmai cloud |
| DNS for `secu100.net`, `pub-cfg.secu100.net`, `caps.secu100.net` at boot | Xiongmai XMEye / "secu100" cloud (seen 2026-11-03) |
| TCP 8186 to the `secu100.net` host, UDP 7999 to `caps.`, TCP 8386 to Alibaba Cloud | Xiongmai cloud entry, capabilities, relay broker (seen 2026-11-03) |
| 8899/tcp ONVIF | common on Xiongmai and other generic firmware |
| 8765/udp outbound every ~13 s, 33-byte datagrams with the serial in ASCII | Xiongmai cloud registration keep-alive (seen 2026-11-03) |
| 6611/tcp outbound to UCloud during app viewing | Xiongmai relay carrying the live stream (seen 2026-11-03) |
| 34569/udp broadcast on the LAN | Xiongmai local discovery |
| Stream frames starting `00 00 01 FC` / `FD` / `FA` / `F9` | Xiongmai media framing: I-frame / P-frame / audio / info |
| 32100/udp, 32108/udp | CS2 Network PPPP / iLnkP2P family |
| 6668/tcp, 6666-6667/udp | Tuya |
| 8000/tcp (SDK) | Hikvision and its OEM rebrands |
| 37777/tcp | Dahua and its OEM rebrands |
| Model string naming `GK7205`, `GK7605` | Goke SoC |
| Model string naming `Hi3516`, `Hi3518` | HiSilicon SoC |
| Model string naming `T31`, `T40` | Ingenic SoC |
| OUI of an AltoBeam, Realtek, MediaTek or Espressif chip | Wi-Fi module vendor only, not the maker |

## Egress patterns

| Pattern in state table / capture | Usual meaning |
|---|---|
| Bidirectional UDP to one host, minutes-long, small packets | P2P registration / NAT pinhole keep-alive |
| Persistent TCP session to a cloud host | control or relay channel |
| Short TCP sessions to the same host on other ports | status / report / relay setup |
| UDP 53 to 1.1.1.1, 8.8.8.8, 114.114.114.114 | hard-coded DNS bypassing the LAN resolver |
| ICMP echo to public resolvers | connectivity ("online") check |
| Large outbound bursts lining up with app viewing | stream relayed through the cloud |
| TCP 443 with SNI of a vendor API | config, time, push, firmware |
| One UDP datagram to a cloud host when the app opens, no reply | failed P2P hole-punch; the session falls back to relay |
| Short TCP to a different provider just before the stream starts | session broker / relay assignment |
| Plain HTTP GET at boot | firmware-update check |
| No DNS in idle or live captures | names cached since boot; capture a reboot |

## Background reading

- SEC Consult, Xiongmai XMEye P2P cloud advisory (2018); CISA ICSA-18-282-06.
- Paul Marrapese, "Abusing P2P to hack 3 million cameras" (CS2/iLnkP2P, 2019).
