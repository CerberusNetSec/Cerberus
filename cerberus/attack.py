"""The MITRE ATT&CK (Enterprise) matrix, with Cerberus's alerts counted in it.

Each detector's playbook names an ATT&CK technique (playbooks.py). A technique
can belong to several tactics; it is shown once, under the playbook's stage
when that is one of the technique's tactics, otherwise under its first one, so
counts are never repeated across columns. Alerts that ATT&CK has no technique
for (correlated compromise, network health) are counted separately.

ATT&CK is a registered trademark of The MITRE Corporation; tactic and technique
names and IDs are from ATT&CK Enterprise.
"""
from __future__ import annotations

from .playbooks import PLAYBOOKS

TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"),
    ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_NAMES = [name for _id, name in TACTICS]

# The tactics ATT&CK lists for each technique Cerberus maps to, in ATT&CK's order.
TECHNIQUE_TACTICS: dict[str, list[str]] = {
    "T1018": ["Discovery"], "T1021": ["Lateral Movement"], "T1046": ["Discovery"],
    "T1048": ["Exfiltration"], "T1071": ["Command and Control"],
    "T1078": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1110": ["Credential Access"], "T1110.003": ["Credential Access"], "T1133": ["Persistence", "Initial Access"],
    "T1190": ["Initial Access"], "T1200": ["Initial Access"], "T1498": ["Impact"], "T1552": ["Credential Access"],
    "T1562": ["Defense Evasion"], "T1571": ["Command and Control"],
}


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def tactic_url(taid: str) -> str:
    return f"https://attack.mitre.org/tactics/{taid}/"


def placement() -> tuple[dict[str, tuple[str, str, str]], dict[str, str]]:
    """({detector: (tactic, technique id, technique name)}, {detector: group}) for those outside ATT&CK."""
    placed, other = {}, {}
    for detector, book in PLAYBOOKS.items():
        technique = book.get("technique")
        if not technique:
            other[detector] = book.get("stage") or "Other"
            continue
        tid, name = technique
        official = TECHNIQUE_TACTICS.get(tid) or [book.get("stage")]
        tactic = book.get("stage") if book.get("stage") in official else official[0]
        if tactic not in TACTIC_NAMES:
            other[detector] = book.get("stage") or "Other"
            continue
        placed[detector] = (tactic, tid, name)
    return placed, other


def matrix(rows: list[dict], names: dict[str, str]) -> dict:
    """rows: per detector and severity, {detector, severity, alerts, occurrences, last_seen}.
    names: detector id -> readable name."""
    placed, other_groups = placement()
    cells: dict[tuple[str, str], dict] = {}
    for detector, (tactic, tid, tname) in placed.items():
        cell = cells.setdefault((tactic, tid), {"id": tid, "name": tname, "url": technique_url(tid), "alerts": 0,
                                                "occurrences": 0, "last_seen": None, "severity": {}, "detectors": []})
        cell["detectors"].append({"id": detector, "name": names.get(detector) or detector.replace("_", " ")})
    other: dict[str, dict] = {}
    for r in rows:
        if r["detector"] in placed:
            tactic, tid, _ = placed[r["detector"]]
            cell = cells[(tactic, tid)]
        else:
            group = other_groups.get(r["detector"], "Other")
            cell = other.setdefault(group, {"name": group, "alerts": 0, "occurrences": 0, "last_seen": None,
                                            "severity": {}, "detectors": []})
            if not any(d["id"] == r["detector"] for d in cell["detectors"]):
                cell["detectors"].append({"id": r["detector"],
                                          "name": names.get(r["detector"]) or r["detector"].replace("_", " ")})
        cell["alerts"] += r["alerts"]
        cell["occurrences"] += r["occurrences"] or 0
        cell["severity"][r["severity"]] = cell["severity"].get(r["severity"], 0) + r["alerts"]
        if r["last_seen"] and (cell["last_seen"] is None or r["last_seen"] > cell["last_seen"]):
            cell["last_seen"] = r["last_seen"]
    tactics = []
    for taid, tname in TACTICS:
        techniques = sorted((c for (t, _), c in cells.items() if t == tname), key=lambda c: c["id"])
        tactics.append({"id": taid, "name": tname, "url": tactic_url(taid), "techniques": techniques,
                        "alerts": sum(c["alerts"] for c in techniques)})
    counted = [c for c in cells.values()]
    return {
        "tactics": tactics,
        "other": sorted(other.values(), key=lambda o: -o["alerts"]),
        "max": max((c["alerts"] for c in counted), default=0),
        "total": sum(c["alerts"] for c in counted),
        "techniques_covered": len(counted),
        "techniques_seen": sum(1 for c in counted if c["alerts"]),
        "tactics_covered": sum(1 for t in tactics if t["techniques"]),
    }
