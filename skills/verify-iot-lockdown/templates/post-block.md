# <Model>: after the internet block (<YYYY-MM-DD>)

Pre-block findings: [`findings.md`](findings.md). Rubric criteria settled here: L1, L2,
L4, L5, L7.

## Baseline (<time, zone>)

| Check | Result |
|---|---|
| RTSP (`ffprobe`) | |
| ONVIF | |
| Device clock vs router | |
| NVR last segment | |
| App on LAN | |
| App on mobile data | |
| Flows (state table) | |

## Block applied (<time, zone>)

Rules (order, description, UUID). States killed: N. IPv6: <handled how>. UPnP: <state>.
Device NTP set to: <router IP / hostname / not settable>.

## Test matrix

| Check | T+10 min | T+1 h | T+24 h |
|---|---|---|---|
| RTSP stream | | | |
| ONVIF | | | |
| NVR recording continuous | | | |
| Clock drift | | | |
| State table LAN-only | | | |
| App on LAN (what works) | | | |
| App off-LAN fails | | | |

## What it keeps trying (firewall log, <window>)

| Destination | Port/proto | Owner | Attempts/h | Seen pre-block? |
|---|---|---|---|---|

## Reboot while blocked (<time>)

Came back on network after <s>; streaming to NVR after <s> / never. Boot attempts:
<fallbacks>. Clock after boot: <correct / wrong>.

## Verdict

Local-only use: <works / works with caveats / does not work>. What broke: <list or none>.
Rubric updates: L1 <status>, L2 <>, L4 <>, L5 <>, L7 <>.
