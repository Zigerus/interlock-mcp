# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Audit chain tests — tamper-evidence against edits, reorders, and drops."""
from interlock.audit import (FileAuditSink, InMemoryAuditSink, GENESIS, verify_chain)


def test_chain_links_and_verifies():
    sink = InMemoryAuditSink()
    for i in range(5):
        sink.record({"kind": "test", "n": i})
    entries = sink.entries()
    assert entries[0]["prev"] == GENESIS
    assert entries[1]["prev"] == entries[0]["hash"]
    ok, detail = verify_chain(entries)
    assert ok, detail


def test_tamper_detected():
    sink = InMemoryAuditSink()
    for i in range(3):
        sink.record({"kind": "test", "n": i})
    entries = sink.entries()
    entries[1]["event"]["n"] = 99            # edit a past entry
    ok, detail = verify_chain(entries)
    assert not ok and "seq 1" in detail


def test_reorder_detected():
    sink = InMemoryAuditSink()
    for i in range(3):
        sink.record({"kind": "test", "n": i})
    entries = sink.entries()
    entries[1], entries[2] = entries[2], entries[1]
    ok, _ = verify_chain(entries)
    assert not ok


def test_drop_detected():
    sink = InMemoryAuditSink()
    for i in range(3):
        sink.record({"kind": "test", "n": i})
    entries = sink.entries()
    del entries[1]                            # drop the middle
    ok, _ = verify_chain(entries)
    assert not ok


def test_file_sink_persists_and_continues_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    s1 = FileAuditSink(path)
    s1.record({"kind": "a"})
    s1.record({"kind": "b"})
    # a fresh sink over the same file must continue the SAME chain
    s2 = FileAuditSink(path)
    s2.record({"kind": "c"})
    entries = s2.entries()
    assert [e["seq"] for e in entries] == [0, 1, 2]
    ok, detail = verify_chain(entries)
    assert ok, detail
