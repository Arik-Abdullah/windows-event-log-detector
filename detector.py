#!/usr/bin/env python3
"""Windows Security Event Log Detector

Reads a CSV or JSON export of Windows Security events and raises L1-style
alerts, mapped to MITRE ATT&CK, as a Markdown triage report.

Detections
  WIN-001  Brute force            4625 x N from one source within a window   T1110
  WIN-002  Password spraying      many distinct accounts from one source     T1110.003
  WIN-003  Success after failures 4624 from a source that just failed        T1078 / T1110
  WIN-004  Account lockout        4740                                       T1110
  WIN-005  Privileged group add   4728 / 4732 / 4756 to an admin group       T1098
           (+ new account 4720 shortly before -> likely persistence)         T1136.001
  WIN-006  Audit log cleared      1102 (Security) / 104 (System)             T1070.001

Usage
  python detector.py events.csv
  python detector.py events.json --threshold 5 --window 5 -o report.md

Standard library only.
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

NO_IP = {"", "-", "::1", "127.0.0.1", "::ffff:127.0.0.1"}
ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins"}
GROUP_ADD_IDS = {4728, 4732, 4756}
LOGON_TYPES_OF_INTEREST = {"2", "3", "7", "10", ""}  # interactive, network, unlock, RDP
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ------------------------------------------------------------------ input ---
def parse_time(value):
    """Parse ISO-8601 (incl. PowerShell 'o' format) or US-style timestamps to naive UTC."""
    s = str(value).strip().replace("Z", "+00:00")
    m = re.match(r"^(.*?\.\d{6})\d*(.*)$", s)  # PowerShell emits 7 fractional digits
    if m:
        s = m.group(1) + m.group(2)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = datetime.strptime(s, "%m/%d/%Y %I:%M:%S %p")
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _pick(row, *names):
    for n in names:
        if n in row and row[n] not in (None, ""):
            return str(row[n]).strip()
    return ""


def normalize(row):
    r = {str(k).strip().lower(): v for k, v in row.items()}
    try:
        event_id = int(_pick(r, "eventid", "id"))
        when = parse_time(_pick(r, "timecreated", "time", "timestamp"))
    except (ValueError, TypeError):
        return None
    return {
        "time": when,
        "id": event_id,
        "computer": _pick(r, "computer", "machinename", "host"),
        "user": _pick(r, "targetusername", "user", "account"),
        "subject": _pick(r, "subjectusername"),
        "ip": _pick(r, "ipaddress", "sourceip", "ip"),
        "ltype": _pick(r, "logontype"),
    }


def load_events(path):
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        if path.lower().endswith(".csv"):
            rows = list(csv.DictReader(fh))
        else:
            text = fh.read().strip()
            try:
                data = json.loads(text)
                rows = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:  # JSON lines
                rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    events = [e for e in (normalize(r) for r in rows) if e]
    events.sort(key=lambda e: e["time"])
    return events


# ------------------------------------------------------------- detections ---
def _source_key(e):
    """Group by source IP when there is one, otherwise by account name."""
    return e["ip"] if e["ip"] not in NO_IP else "user:" + e["user"].lower()


def _burst(times, window):
    """Largest number of events inside `window`; returns (count, start_index)."""
    best, best_start, j = 0, 0, 0
    for i in range(len(times)):
        while times[i] - times[j] > window:
            j += 1
        if i - j + 1 > best:
            best, best_start = i - j + 1, j
    return best, best_start


def detect_bruteforce(events, threshold=5, window_min=5):
    window = timedelta(minutes=window_min)
    fails = defaultdict(list)
    for e in events:
        if e["id"] == 4625:
            fails[_source_key(e)].append(e)
    successes = [e for e in events if e["id"] == 4624 and e["ltype"] in LOGON_TYPES_OF_INTEREST]

    findings = []
    for key, evs in fails.items():
        times = [e["time"] for e in evs]
        count, start = _burst(times, window)
        if count < threshold:
            continue
        in_window = [e for e in evs if times[start] <= e["time"] <= times[start] + window]
        users = sorted({e["user"] for e in in_window if e["user"]})
        shown = key if not key.startswith("user:") else key[5:] + " (no source IP)"
        base = {
            "time": times[start], "computer": evs[0]["computer"],
            "evidence": [f"{count} failed logons (4625) within {window_min} min, "
                         f"{times[start]:%H:%M:%S} - {in_window[-1]['time']:%H:%M:%S}",
                         f"Accounts targeted ({len(users)}): {', '.join(users[:8])}"],
        }
        spray = len(users) >= threshold
        if spray:
            findings.append({**base, "rule": "WIN-002", "severity": "MEDIUM", "attack": "T1110.003",
                             "title": f"Password spraying from {shown}",
                             "action": "Block or monitor the source, check whether any targeted account "
                                       "logged on successfully, notify the account owners."})
        else:
            findings.append({**base, "rule": "WIN-001", "severity": "MEDIUM", "attack": "T1110",
                             "title": f"Brute-force logon attempts from {shown}",
                             "action": "Block or monitor the source, review the targeted account, "
                                       "check for later successful logons."})
        later = [s for s in successes
                 if s["time"] >= times[start]
                 and (_source_key(s) == key or (key.startswith("user:") and s["user"].lower() == key[5:]))]
        if later:
            s = later[0]
            findings.append({
                "rule": "WIN-003", "severity": "HIGH", "attack": "T1078, T1110", "time": s["time"],
                "computer": s["computer"],
                "title": f"Successful logon (4624) as '{s['user']}' after failures from {shown}",
                "evidence": [f"Logon type {s['ltype'] or 'n/a'} at {s['time']:%H:%M:%S} on {s['computer'] or 'n/a'}",
                             "Same source had a failed-logon burst just before"],
                "action": "ESCALATE to L2: possible account compromise. Isolate the host if confirmed, "
                          "reset credentials, review activity after the logon.",
            })
    return findings


def detect_lockouts(events):
    by_user = defaultdict(list)
    for e in events:
        if e["id"] == 4740:
            by_user[e["user"].lower()].append(e)
    return [{
        "rule": "WIN-004", "severity": "MEDIUM", "attack": "T1110", "time": evs[0]["time"],
        "computer": evs[0]["computer"], "title": f"Account lockout: {evs[0]['user']}",
        "evidence": [f"{len(evs)} lockout event(s) (4740), first at {evs[0]['time']:%H:%M:%S}"],
        "action": "Check the source of the bad passwords; confirm with the user whether it was them.",
    } for evs in by_user.values()]


def detect_privilege_changes(events, link_minutes=30):
    findings = []
    created = [e for e in events if e["id"] == 4720]
    for e in events:
        if e["id"] in GROUP_ADD_IDS and e["user"].lower() in ADMIN_GROUPS:
            recent = [c for c in created if timedelta(0) <= e["time"] - c["time"] <= timedelta(minutes=link_minutes)
                      and c["computer"] == e["computer"]]
            evidence = [f"Event {e['id']}: member added to '{e['user']}' by '{e['subject'] or 'unknown'}' "
                        f"at {e['time']:%H:%M:%S} on {e['computer'] or 'n/a'}"]
            title = f"Privileged group membership change ({e['user']})"
            attack = "T1098"
            if recent:
                c = recent[-1]
                evidence.append(f"Account '{c['user']}' was created (4720) by '{c['subject'] or 'unknown'}' "
                                f"{int((e['time'] - c['time']).total_seconds() // 60)} min earlier")
                title += " shortly after a new account was created"
                attack = "T1136.001, T1098"
            findings.append({
                "rule": "WIN-005", "severity": "HIGH", "attack": attack, "time": e["time"],
                "computer": e["computer"], "title": title, "evidence": evidence,
                "action": "ESCALATE to L2 unless this matches an approved change ticket. "
                          "Verify with the actor and the asset owner.",
            })
    return findings


def detect_log_clearing(events):
    out = []
    for e in events:
        if e["id"] in (1102, 104):
            log = "Security" if e["id"] == 1102 else "System"
            out.append({
                "rule": "WIN-006", "severity": "HIGH", "attack": "T1070.001", "time": e["time"],
                "computer": e["computer"], "title": f"{log} event log cleared on {e['computer'] or 'host'}",
                "evidence": [f"Event {e['id']} at {e['time']:%H:%M:%S}, actor: {e['subject'] or e['user'] or 'unknown'}"],
                "action": "ESCALATE to L2: clearing logs is a common anti-forensics step. "
                          "Preserve remaining logs and review activity just before this time.",
            })
    return out


def run_all(events, threshold=5, window_min=5):
    findings = (detect_bruteforce(events, threshold, window_min) + detect_lockouts(events)
                + detect_privilege_changes(events) + detect_log_clearing(events))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["time"]))
    return findings


# ----------------------------------------------------------------- report ---
def build_report(path, events, findings):
    sev = defaultdict(int)
    for f in findings:
        sev[f["severity"]] += 1
    span = f"{events[0]['time']:%Y-%m-%d %H:%M} to {events[-1]['time']:%Y-%m-%d %H:%M} UTC" if events else "n/a"
    out = ["# Windows Security Event Triage Report", "",
           f"- Source: `{path}`", f"- Events analysed: {len(events)} ({span})",
           f"- Alerts: {len(findings)} (HIGH {sev['HIGH']}, MEDIUM {sev['MEDIUM']}, LOW {sev['LOW']})", ""]
    if not findings:
        out.append("No detections fired. Close as benign.")
    for n, f in enumerate(findings, 1):
        out += [f"## Alert {n}: {f['severity']} - {f['title']}", "",
                f"- Rule: {f['rule']}  |  ATT&CK: {f['attack']}", f"- Host: {f['computer'] or 'n/a'}"]
        out += [f"- Evidence: {line}" for line in f["evidence"]]
        out += [f"- Recommended action: {f['action']}", ""]
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Windows Security event log detector")
    p.add_argument("file", help="CSV or JSON export (see README for the PowerShell export)")
    p.add_argument("--threshold", type=int, default=5, help="failed logons needed to alert")
    p.add_argument("--window", type=int, default=5, help="window in minutes")
    p.add_argument("-o", "--output")
    args = p.parse_args(argv)

    events = load_events(args.file)
    report = build_report(args.file, events, run_all(events, args.threshold, args.window))
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    sys.exit(main())
