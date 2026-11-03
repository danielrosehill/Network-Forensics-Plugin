# Local-Only Security Rubric, version 1 (2026-11-03)

Rates a networked device, typically an IP camera, on two questions:

1. **Local-only viability (L, 50 points):** can you cut it off from the internet and keep
   using it (RTSP/ONVIF to your own NVR, the vendor app on the LAN)?
2. **Cloud exposure (E, 50 points):** while it *is* connected, how much does it put at
   risk (cleartext media, identifiers, hard-coded infrastructure, weak services)?

Weights, grade bands and caps are implemented in `scripts/score.py`. If you change them
here, change them there and bump the version. Scores under different versions are not
comparable.

## Statuses and evidence

Each criterion gets a **status** and an **evidence** level.

| Status | Points |
|---|---|
| `pass` | full weight |
| `partial` | half weight |
| `fail` | 0 |
| `unknown` | 0, and listed as untested; the score is *provisional* until none remain |
| `na` | dropped from the denominator (e.g. E5 for a device with no media) |

| Evidence | Meaning |
|---|---|
| `tested` | We observed it on this unit (capture, state table, probe, post-block test) |
| `documented` | The vendor's own docs, or a primary source such as the integration's docs. Cite the URL |
| `inferred` | Reasoned from indirect evidence (e.g. payload has no codec markers and high entropy, so it is assumed encrypted). Say what it rests on |
| `none` | Only with `unknown` |

Rules: `fail` needs `tested` or `documented` evidence. Never fail a device on inference
alone; leave it `unknown`. A claim about the vendor that has no source stays `unknown`.
A `documented` pass is upgraded to `tested` when we test it.

## Criteria

### Local-only viability (50)

| ID | Weight | Criterion | pass | partial | fail |
|---|---|---|---|---|---|
| L1 | 15 | **Local streams survive an internet block** | RTSP/ONVIF stream and NVR recording continuous ≥24 h after block + state kill | Works, but drops, stalls or needs a reboot | Stops streaming, or refuses local auth, when blocked |
| L2 | 5 | Vendor app/client works on the LAN while blocked | Live view, playback and settings on the LAN | Live view only, or settings locked | App cannot reach it without the cloud |
| L3 | 5 | Setup and re-pair without internet or vendor account | Fully offline (web UI, AP mode or LAN app) | Internet or account needed for first setup only | Every re-pair or reset needs the cloud |
| L4 | 5 | Cloud/P2P switch on the device, and egress stops | Switch exists and the state table shows egress stops | Switch exists, but egress continues or is unverified | No switch |
| L5 | 5 | Honours LAN DNS and a local NTP server | DHCP-provided DNS only, NTP settable to the router | One of the two | Neither |
| L6 | 5 | RTSP and ONVIF available without the vendor cloud | Both, on or switchable on locally | One of them, or only via the vendor's cloud-linked app | Neither |
| L7 | 10 | Degrades cleanly when blocked | No reboot loop, no feature lockout, clock correct, retries ≤ ~6/min sustained | One of those problems | Several, or it becomes unusable over days |

### Cloud exposure (50)

| ID | Weight | Criterion | pass | partial | fail |
|---|---|---|---|---|---|
| E1 | 15 | **Media leaving the LAN is encrypted** | No codec start codes, vendor media headers or audio silence patterns in relay/P2P payload | Only metadata or thumbnails readable | Any cleartext audio or video frames |
| E2 | 5 | No identifiers or credentials in cleartext egress | None found | Weakly obfuscated (fixed public key) | Serial/cloud ID, account or password readable |
| E3 | 5 | Cloud reached by name via the LAN resolver | All names via DHCP DNS, no IPs dialled without a lookup (servers handed out by the vendor's own protocol count as looked up) | Names via LAN, but some hard-coded IPs | Hard-coded public resolvers, or most infrastructure by hard-coded IP |
| E4 | 5 | Small cloud footprint | One operator (vendor's own, or one hosting provider) | Two | Three or more operators |
| E5 | 5 | No media egress when nobody is viewing | Idle windows show keep-alives only | Periodic snapshots/thumbnails | Continuous or event media upload not configured by the owner |
| E6 | 5 | No legacy or weak local services | Only authenticated, standard services (RTSP Digest, ONVIF WS-Security, vendor protocol with login) | One weak point (e.g. RTSP Basic, open telnet with a non-default password) | Xiongmai DVRIP 34567, CS2 PPPP 32100, open telnet, unauthenticated media, or default credentials |
| E7 | 5 | No known unpatched vulnerabilities | No CVEs found for this model/firmware line (say "none found", with the search) | CVEs for this line fixed in a later firmware than installed | Public advisories for the platform with no fix |
| E8 | 5 | Offline firmware update path | Vendor publishes firmware images for this hardware ID | Images exist, but not for this hardware ID/region | Updates only via the cloud |

## Grade

`score = points earned / points applicable × 100`

| Grade | Score |
|---|---|
| A | ≥ 85 |
| B | ≥ 70 |
| C | ≥ 55 |
| D | ≥ 40 |
| F | < 40 |

**Red flags cap the grade** whatever the points:

- L1 `fail`: grade F. The device is not usable local-only.
- E1 `fail`: grade D at best. Cleartext room audio or video crosses the internet.

A provisional score is reported with its **ceiling**, the score if every `unknown`
passed. A device whose ceiling is below C cannot be rescued by testing.

## What the rubric does not cover

Physical security, the phone app's own privacy (trackers, permissions), cloud account
security and video quality. Note anything material under "Other observations" in the
device's score file. It does not change the number.
