"""Detector state to and from JSON.

Detectors keep their working state (sliding windows, counters, learned
baselines) in ordinary Python containers keyed by tuples, plus a few small
classes. This module turns that into plain JSON and back, so the state can
outlive a restart now and move between nodes later.

It is deliberately not pickle: decoding only ever builds the container types
below and classes registered with @persistent, so a tampered snapshot cannot
run code. Insertion order is kept, because several windows evict oldest-first.
"""
from __future__ import annotations

from collections import Counter, deque

_CLASSES: dict[str, type] = {}


def persistent(cls):
    """Register a class whose instances may appear in detector state."""
    _CLASSES[cls.__name__] = cls
    return cls


def _attrs(obj) -> list[str]:
    slots = [s for klass in type(obj).__mro__ for s in getattr(klass, "__slots__", ())]
    return slots or list(vars(obj))


def encode(value):
    """Python value -> JSON-compatible value."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [encode(v) for v in value]
    if isinstance(value, tuple):
        return {"T": [encode(v) for v in value]}
    if isinstance(value, Counter):
        return {"C": [[encode(k), v] for k, v in value.items()]}
    if isinstance(value, dict):
        return {"M": [[encode(k), encode(v)] for k, v in value.items()]}
    if isinstance(value, deque):
        return {"Q": [encode(v) for v in value], "n": value.maxlen}
    if isinstance(value, (set, frozenset)):
        return {"S": [encode(v) for v in value]}
    name = type(value).__name__
    if _CLASSES.get(name) is type(value):
        return {"O": name, "a": {attr: encode(getattr(value, attr)) for attr in _attrs(value) if hasattr(value, attr)}}
    raise TypeError(f"cannot persist a {name}")


def decode(value):
    """Inverse of encode."""
    if not isinstance(value, (list, dict)):
        return value
    if isinstance(value, list):
        return [decode(v) for v in value]
    if "T" in value:
        return tuple(decode(v) for v in value["T"])
    if "M" in value:
        return {decode(k): decode(v) for k, v in value["M"]}
    if "C" in value:
        return Counter({decode(k): v for k, v in value["C"]})
    if "Q" in value:
        return deque((decode(v) for v in value["Q"]), maxlen=value.get("n"))
    if "S" in value:
        return {decode(v) for v in value["S"]}
    if "O" in value:
        cls = _CLASSES.get(value["O"])
        if cls is None:
            raise ValueError(f"unknown state class {value['O']!r}")
        obj = cls.__new__(cls)
        for attr, item in value["a"].items():
            setattr(obj, attr, decode(item))
        return obj
    raise ValueError("unrecognised state value")
