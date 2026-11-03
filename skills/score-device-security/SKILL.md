---
name: score-device-security
description: Rate an IoT device (IP camera, hub) for local-only use and cloud exposure on a fixed 100-point rubric, from its forensics findings and vendor docs. Produces a score file, a grade with red flags, and the list of what is still untested.
---

# Score a device's security (Local-Only Security Rubric)

Turns what `lockdown-iot-device` found (and what `verify-iot-lockdown` tested) into a
comparable score. It answers two questions: **can it run with the internet cut off**,
and **how much does it expose while connected**. The rubric is
`references/rubric.md`. Read it before scoring. Weights, caps and grades are computed by
`scripts/score.py`, never by hand.

## Inputs

- The device's dossier and forensics findings (idle, live-view, boot captures), and the
  post-block record if one exists.
- The raw captures, if a payload question (E1, E2) is still open.
- The repo to write into. Default layout: `scores/<device-slug>.json`, plus a
  `scoring.md` summary table.

## Steps

1. **Copy `templates/score.json`** to `scores/<device-slug>.json`. Every criterion starts
   `unknown`.
2. **Fill each criterion from evidence you already have.** For each one, set `status`,
   `evidence` (`tested` / `documented` / `inferred`), a one-line `note` and a `source`
   (repo path or URL). Rules that keep the score honest:
   - `fail` needs `tested` or `documented` evidence. Inference alone leaves it `unknown`.
   - Vendor claims need the vendor's own page, cited. A forum post is context, not
     evidence. Put it in the note.
   - Do not carry CVEs across models. "None found for this model" needs the search
     stated.
   - High entropy alone does **not** prove encryption: compressed video is high-entropy
     too. For E1, check what follows `00 00 00 01` start codes (H.264 NAL headers `0x67`
     SPS, `0x68` PPS, `0x65` IDR, `0x41` P; HEVC `0x40`/`0x42`/`0x44`/`0x26`/`0x02`),
     look for vendor media headers (Xiongmai `00 00 01 FC/FD/FA`, Reolink Baichuan
     `00dc`/`01dc`/`05wb`) and A-law/µ-law silence runs, and compare marker counts with
     chance (`bytes / 2^32` for a 4-byte pattern). Snippet below.
3. **Research the vendor-side criteria** (L2, L3, L4, L6, E7, E8) when they are not
   testable yet. Use a cheap research subagent (model sonnet or haiku) that returns
   claims with URLs and CONFIRMED / REPORTED / UNKNOWN labels. Only CONFIRMED claims
   become `documented`.
4. **Run the scorer:**
   ```bash
   python3 scripts/score.py scores/<device>.json             # per-criterion table
   python3 scripts/score.py --table scores/*.json            # summary across devices
   python3 scripts/score.py --json scores/*.json             # machine output
   ```
5. **Publish** the per-device table in the device dossier (or `scoring.md`) and the
   summary row in the repo README. Always show the grade as *provisional* with its
   ceiling and the untested IDs until none remain.
6. **Re-score after `verify-iot-lockdown`.** L1, L2, L4 and L7 can only be settled by the
   post-block test. Bump `assessed`.

## E1/E2 payload check (Python, scapy via uv)

```bash
uv run --with scapy python -I - cap.pcap <relay-ip> <<'EOF'
import sys, re, collections, math
from scapy.all import rdpcap, IP, UDP, TCP
d = bytearray()
for p in rdpcap(sys.argv[1]):
    if IP in p and p[IP].dst == sys.argv[2] and (UDP in p or TCP in p):
        d += bytes((p[UDP] if UDP in p else p[TCP]).payload)
d = bytes(d); n = len(d)
idx = [m.start() for m in re.finditer(b'\x00\x00\x00\x01', d)]
print('bytes', n, 'start codes', len(idx), 'expected by chance', round(n / 2**32, 3))
print('byte after start code', collections.Counter(d[i+4] for i in idx if i+4 < n).most_common(8))
for name, m in [('XM I', b'\x00\x00\x01\xfc'), ('XM P', b'\x00\x00\x01\xfd'), ('XM audio', b'\x00\x00\x01\xfa'),
                ('BC 00dc', b'00dc'), ('BC 01dc', b'01dc'), ('BC 05wb', b'05wb')]:
    print(name, d.count(m))
c = collections.Counter(d); print('entropy', round(-sum(v/n*math.log2(v/n) for v in c.values()), 3))
print('printable runs', collections.Counter(re.findall(rb'[\x20-\x7e]{8,}', d)).most_common(5))
EOF
```

Start codes followed by valid NAL header bytes, or vendor media headers well above
chance, mean cleartext media (`fail`, `tested`). Start codes followed by `0x00` are
framing integers, not NAL units. No markers plus entropy near 8 means `pass`, `inferred`.

## Output

- `scores/<device>.json` (machine-readable, the source of truth).
- The scorer's table in the device dossier or `scoring.md`, and a summary row in the
  README.
- In the reply: score, grade, red flags, ceiling, and the untested criteria with the
  test that would settle each.
