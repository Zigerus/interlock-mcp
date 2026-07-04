# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Append-only, hash-chained audit log — a tamper-evident record of every decision.

Each event is chained to the one before it: ``entry_hash = H(prev_hash || canonical(entry))``.
Altering or dropping any past entry breaks the chain from that point on, and
:func:`verify_chain` detects it. This gives a cheap, verifiable "what did the interlock
actually do, and in what order" — the property compliance and post-incident review need.

Sinks are pluggable: an in-memory sink for tests/embedding, a JSONL file sink for a
durable single-node deployment; bring your own for a log pipeline.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

import rfc8785

__all__ = ["AuditSink", "InMemoryAuditSink", "FileAuditSink", "verify_chain", "GENESIS"]

GENESIS = "0" * 64  # prev_hash of the first entry


def _entry_hash(prev_hash: str, entry_without_hash: dict) -> str:
    payload = prev_hash.encode() + rfc8785.dumps(entry_without_hash)
    return hashlib.sha256(payload).hexdigest()


@runtime_checkable
class AuditSink(Protocol):
    def record(self, event: dict) -> dict:
        """Append an event; return the stored entry (with seq/ts/prev/hash added)."""
        ...

    def entries(self) -> list[dict]: ...


def _stamp(event: dict, seq: int, prev: str) -> dict:
    entry = {
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "prev": prev,
        "event": event,
    }
    entry["hash"] = _entry_hash(prev, {k: entry[k] for k in ("seq", "ts", "prev", "event")})
    return entry


class InMemoryAuditSink:
    def __init__(self) -> None:
        self._entries: list[dict] = []

    def record(self, event: dict) -> dict:
        prev = self._entries[-1]["hash"] if self._entries else GENESIS
        entry = _stamp(event, len(self._entries), prev)
        self._entries.append(entry)
        return entry

    def entries(self) -> list[dict]:
        return list(self._entries)


class FileAuditSink:
    """Append each entry as one JSON line. The chain head is derived from the last line,
    so restarts continue the same chain."""
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _tail(self) -> tuple[int, str]:
        seq, prev = 0, GENESIS
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)
                    seq, prev = last["seq"] + 1, last["hash"]
        return seq, prev

    def record(self, event: dict) -> dict:
        seq, prev = self._tail()
        entry = _stamp(event, seq, prev)
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def entries(self) -> list[dict]:
        out = []
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    out.append(json.loads(line))
        return out


def verify_chain(entries: list[dict]) -> tuple[bool, str]:
    """Verify the hash chain. Returns (ok, detail). Detects reordering, edits, and drops."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return False, f"seq gap/reorder at index {i}: seq={e.get('seq')}"
        if e.get("prev") != prev:
            return False, f"broken link at seq {i}: prev={e.get('prev')!r} expected {prev!r}"
        recomputed = _entry_hash(prev, {k: e.get(k) for k in ("seq", "ts", "prev", "event")})
        if recomputed != e.get("hash"):
            return False, f"tampered entry at seq {i}: hash mismatch"
        prev = e["hash"]
    return True, f"chain intact ({len(entries)} entries)"
