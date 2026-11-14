"""Each detector's declared partition key really does let its work be divided.

For clustering, events will be spread over several copies of a detector by the
key it declares (Detector.partition). That is only correct if every event that
can affect one alert reaches the same copy. This runs the reference traffic
from tests/golden.py through one copy of each detector, then through four
copies with the events divided by the declared key, and requires exactly the
same alerts. It also checks each detector's declared event types: a detector
must ignore every other type of event.
"""
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import golden  # noqa: E402
from cerberus.connectors import ConnectorRegistry  # noqa: E402
from cerberus.detectors import build_detectors  # noqa: E402
from cerberus.syslog_parser import parse_syslog  # noqa: E402
from tools import simulate  # noqa: E402

SHARDS = 4
TICK = golden.TICK


def events():
    """The reference timeline as normalised events, devices identified by hostname."""
    registry = ConnectorRegistry()
    out = []
    for offset, line in golden.timeline(simulate):
        parsed = parse_syslog(line.encode())
        ev = registry.build_event(parsed, golden.START + offset, parsed["hostname"] or "10.255.0.1", "10.255.0.1")
        if ev.hostname and ev.device != ev.hostname:
            ev.device = ev.hostname
        out.append(ev)
    return out


EVENTS = events()


def configured(det):
    if det.id == "watchlist":
        det.configure({**det.settings(), "entries": "45.77.0.0/16"})
    return det


def fresh(detector_id: str):
    return configured(next(d for d in build_detectors() if d.id == detector_id))


def run(detector_id: str, shards: int) -> list[tuple]:
    copies = [fresh(detector_id) for _ in range(shards)]
    found: list[tuple] = []

    def emitter(now):
        return lambda c: found.append((now, c.detector, c.entity, c.severity, c.title, c.description, repr(c.details)))

    def copy_for(key: str):
        return copies[zlib.crc32(key.encode()) % shards]

    # Correlation also reads the alert stream; feed it every other detector's alerts,
    # divided by the alert's source address like its events.
    others = [configured(d) for d in build_detectors() if d.id != detector_id] if detector_id == "correlation" else []

    next_tick = golden.START + TICK
    for ev in EVENTS:
        while next_tick <= ev.ts:
            for c in copies:
                c.tick(next_tick, emitter(next_tick))
            for o in others:
                o.tick(next_tick, lambda cand, t=next_tick: copy_for(cand.src_ip or "").on_alert(cand, t, emitter(t)))
            next_tick += TICK
        for o in others:
            o.process(ev, ev.ts, lambda cand, t=ev.ts: copy_for(cand.src_ip or "").on_alert(cand, t, emitter(t)))
        target = copies[0] if shards == 1 else copy_for(copies[0].partition_key(ev))
        target.process(ev, ev.ts, emitter(ev.ts))
    return sorted(found)


# Detectors that read events through process(). The others (rate baselines, silence,
# new devices, topology) are fed per device by the engine or the SNMP poller, so
# dividing them by device is division by their own dictionary key.
SHARDABLE = [d.id for d in build_detectors() if d.partition not in ("none", "split") and d.event_types != frozenset()]


@pytest.mark.parametrize("detector_id", SHARDABLE)
def test_divided_by_its_key_a_detector_finds_the_same(detector_id):
    whole = run(detector_id, 1)
    divided = run(detector_id, SHARDS)
    assert divided == whole
    # Make sure the reference traffic exercises it, so the comparison means something.
    if detector_id not in ("admin_access", "risk_ports", "brute_force", "link_flap", "notable", "threat"):
        assert whole, f"{detector_id} raised nothing on the reference traffic"


def test_undivided_detectors_are_the_known_ones():
    # credential_attacks keys on source (spraying) and on account (distributed guessing):
    # it must be split in two before clustering. The rest read no events themselves.
    assert {d.id: d.partition for d in build_detectors() if d.partition in ("none", "split")} == {
        "credential_attacks": "split"}


@pytest.mark.parametrize("detector_id", [d.id for d in build_detectors()])
def test_declared_event_types_cover_everything_a_detector_reacts_to(detector_id):
    """Feeding a detector every event, or only its declared types, gives the same alerts."""
    def go(only_declared: bool) -> list:
        det = fresh(detector_id)
        found = []
        next_tick = golden.START + TICK
        for ev in EVENTS:
            while next_tick <= ev.ts:
                det.tick(next_tick, lambda c, t=next_tick: found.append((t, c.entity, c.title)))
                next_tick += TICK
            if only_declared and det.event_types is not None and ev.event_type not in det.event_types:
                continue
            det.process(ev, ev.ts, lambda c, t=ev.ts: found.append((t, c.entity, c.title)))
        return found
    assert go(True) == go(False)
