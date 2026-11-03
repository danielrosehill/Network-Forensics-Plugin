#!/usr/bin/env python3
"""Score an IoT device (IP camera etc.) against the Local-Only Security Rubric.

Usage:
  score.py <device.json> [<device.json> ...]         # human table per device
  score.py --json <device.json> ...                  # machine output
  score.py --table <device.json> ...                 # one markdown summary table

Input JSON (one file per device; see templates/score.json):
  {"device": "...", "rubric_version": 1, "assessed": "YYYY-MM-DD",
   "criteria": {"L1": {"status": "pass|partial|fail|unknown|na",
                       "evidence": "tested|documented|inferred|none",
                       "note": "...", "source": "path or URL"}, ...}}

Rubric: references/rubric.md. Weights and caps live here and nowhere else.
"""
import json
import sys

RUBRIC_VERSION = 1

# id: (weight, section, short name)
CRITERIA = {
    "L1": (15, "local", "Local streams survive an internet block"),
    "L2": (5, "local", "Vendor app/client works on the LAN while blocked"),
    "L3": (5, "local", "Setup and re-pair without internet or vendor account"),
    "L4": (5, "local", "Cloud/P2P switch on the device, and egress stops"),
    "L5": (5, "local", "Honours LAN DNS and a local NTP server"),
    "L6": (5, "local", "RTSP and ONVIF available without the vendor cloud"),
    "L7": (10, "local", "Degrades cleanly when blocked"),
    "E1": (15, "exposure", "Media leaving the LAN is encrypted"),
    "E2": (5, "exposure", "No identifiers or credentials in cleartext egress"),
    "E3": (5, "exposure", "Cloud reached by name via the LAN resolver"),
    "E4": (5, "exposure", "Small cloud footprint (one operator)"),
    "E5": (5, "exposure", "No media egress when nobody is viewing"),
    "E6": (5, "exposure", "No legacy or weak local services"),
    "E7": (5, "exposure", "No known unpatched vulnerabilities"),
    "E8": (5, "exposure", "Offline firmware update path"),
}
FACTOR = {"pass": 1.0, "partial": 0.5, "fail": 0.0, "unknown": 0.0}
GRADES = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]
ORDER = "ABCDF"
# Red flags: a failed criterion caps the grade whatever the points.
CAPS = {"L1": ("F", "not usable local-only"), "E1": ("D", "cleartext media off the LAN")}


def grade(pct):
    return next(g for t, g in GRADES if pct >= t)


def worse(a, b):
    return a if ORDER.index(a) > ORDER.index(b) else b


def score(doc):
    if doc.get("rubric_version") != RUBRIC_VERSION:
        raise SystemExit(f"{doc.get('device')}: rubric_version {doc.get('rubric_version')} != {RUBRIC_VERSION}")
    crit = doc["criteria"]
    missing = [k for k in CRITERIA if k not in crit]
    if missing:
        raise SystemExit(f"{doc.get('device')}: missing criteria {missing} (use status 'unknown')")
    earned = pending = applicable = 0.0
    sections = {"local": [0.0, 0.0], "exposure": [0.0, 0.0]}
    evidence = {}
    flags = []
    rows = []
    for k, (w, sec, name) in CRITERIA.items():
        c = crit[k]
        st = c["status"]
        if st == "na":
            rows.append((k, name, w, st, None, c.get("evidence", "none")))
            continue
        if st not in FACTOR:
            raise SystemExit(f"{k}: bad status {st}")
        pts = w * FACTOR[st]
        applicable += w
        earned += pts
        sections[sec][0] += pts
        sections[sec][1] += w
        if st == "unknown":
            pending += w
        else:
            evidence[c.get("evidence", "none")] = evidence.get(c.get("evidence", "none"), 0) + 1
        if k in CAPS and st == "fail":
            flags.append((k, *CAPS[k]))
        rows.append((k, name, w, st, pts, c.get("evidence", "none")))
    pct = 100 * earned / applicable
    pct_max = 100 * (earned + pending) / applicable
    cap = "A"
    for _, g, _ in flags:
        cap = worse(cap, g)
    return {
        "device": doc["device"],
        "assessed": doc.get("assessed"),
        "score": round(pct, 1),
        "score_if_unknowns_pass": round(pct_max, 1),
        "grade": worse(grade(pct), cap),
        "grade_ceiling": worse(grade(pct_max), cap),
        "final": pending == 0,
        "local_only": f"{sections['local'][0]:g}/{sections['local'][1]:g}",
        "exposure": f"{sections['exposure'][0]:g}/{sections['exposure'][1]:g}",
        "red_flags": [f"{k}: {why} (cap {g})" for k, g, why in flags],
        "unknown": [r[0] for r in rows if r[3] == "unknown"],
        "evidence_counts": evidence,
        "rows": rows,
    }


def human(r):
    out = [f"## {r['device']} (assessed {r['assessed']}, rubric v{RUBRIC_VERSION})", "",
           "| ID | Criterion | Weight | Status | Points | Evidence |", "|---|---|---|---|---|---|"]
    for k, name, w, st, pts, ev in r["rows"]:
        out.append(f"| {k} | {name} | {w} | {st} | {'-' if pts is None else f'{pts:g}'} | {ev} |")
    state = "final" if r["final"] else f"provisional, {len(r['unknown'])} untested: {', '.join(r['unknown'])}"
    out += ["", f"**Score {r['score']} / 100, grade {r['grade']}** ({state}). "
            f"Local-only {r['local_only']}, exposure {r['exposure']}."]
    if not r["final"]:
        out.append(f"If every untested criterion passed: {r['score_if_unknowns_pass']}, grade {r['grade_ceiling']}.")
    if r["red_flags"]:
        out.append("Red flags: " + "; ".join(r["red_flags"]) + ".")
    return "\n".join(out)


def table(rs):
    out = ["| Device | Score | Grade | Ceiling | Local-only | Exposure | Red flags | Untested |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rs:
        out.append(f"| {r['device']} | {r['score']} | {r['grade']} | {r['grade_ceiling']} ({r['score_if_unknowns_pass']}) "
                   f"| {r['local_only']} | {r['exposure']} | {'; '.join(r['red_flags']) or 'none'} "
                   f"| {', '.join(r['unknown']) or 'none'} |")
    return "\n".join(out)


def main(argv):
    mode = "human"
    if argv and argv[0] in ("--json", "--table"):
        mode, argv = argv[0][2:], argv[1:]
    if not argv:
        raise SystemExit(__doc__)
    rs = [score(json.load(open(p))) for p in argv]
    if mode == "json":
        for r in rs:
            r.pop("rows")
        print(json.dumps(rs, indent=2))
    elif mode == "table":
        print(table(rs))
    else:
        print("\n\n".join(human(r) for r in rs))


if __name__ == "__main__":
    main(sys.argv[1:])
