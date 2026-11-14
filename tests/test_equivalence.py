"""The current code must detect and store exactly what the 0.2.0 release did.

The reference in tests/golden/v0.2.0.json was recorded by tests/golden.py from
a checkout of the v0.2.0 tag. A deliberate change in behaviour means
re-recording it, and saying why in the commit.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402

REFERENCE = Path(__file__).resolve().parent / "golden" / "v0.2.0.json"


def test_same_alerts_and_storage_as_v0_2_0(tmp_path):
    expected = json.loads(REFERENCE.read_text(encoding="utf-8"))
    actual = json.loads(json.dumps(golden.run(None, tmp_path)))  # same JSON round trip as the reference
    # Alerts first, one by one, so a difference reads as a difference in an alert.
    assert len(actual["alerts"]) == len(expected["alerts"]), [a["title"] for a in actual["alerts"]]
    for got, want in zip(actual["alerts"], expected["alerts"]):
        assert got == want
    for table in ("events", "stats_minute", "port_minute", "devices"):
        assert actual[table] == expected[table], table


def test_restarting_midway_changes_nothing(tmp_path):
    """Detector state saved and restored across restarts: the same run, stopped and
    restarted three times (during baseline learning, mid-attack and during the
    beacon), detects and stores exactly what an uninterrupted run does."""
    expected = json.loads(REFERENCE.read_text(encoding="utf-8"))
    actual = json.loads(json.dumps(golden.run(None, tmp_path, restarts=(0.3, 0.62, 0.8))))
    assert [a["title"] for a in actual["alerts"]] == [a["title"] for a in expected["alerts"]]
    assert actual == expected
