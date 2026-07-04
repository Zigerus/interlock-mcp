# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Approval gate tests — hash-bound, one-shot, TTL, tamper-evidence."""
from datetime import datetime, timedelta, timezone

import pytest
from conftest import build_plan

from interlock.approval import (FileStore, InMemoryStore, approve, check_release,
                                propose, reject)


def _clock(dt):
    return lambda: dt


def test_propose_then_approve_binds_hash():
    store = InMemoryStore()
    p = propose(store, build_plan())
    assert p["status"] == "proposed"
    a = approve(store, p["plan_id"], approver="nathan", reasoning="lgtm")
    assert a["status"] == "approved"
    assert a["approval"]["binding"]["plan_hash"] == p["plan_hash"]
    assert a["approval"]["approved_by"] == "nathan"


def test_approve_requires_proposed_state():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p2"))
    approve(store, "p2", approver="n")
    with pytest.raises(ValueError):
        approve(store, "p2", approver="n")   # already approved -> not 'proposed'


def test_release_ok_for_fresh_approval():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p3"))
    a = approve(store, "p3", approver="n")
    assert check_release(a).ok


def test_release_refused_when_not_approved():
    assert not check_release(build_plan(status="proposed")).ok


def test_release_refused_after_post_approval_body_edit():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p4"))
    a = approve(store, "p4", approver="n")
    a["body"]["stages"][0]["params"]["replicas"] = "999"   # tamper AFTER approval
    d = check_release(a)
    assert not d.ok and "hash mismatch" in d.reason


def test_release_refused_when_expired():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p5"))
    t0 = datetime(2026, 7, 4, 12, 0, tzinfo=timezone.utc)
    a = approve(store, "p5", approver="n", now=_clock(t0))
    later = _clock(t0 + timedelta(hours=2))
    assert not check_release(a, ttl_seconds=3600, now=later).ok
    assert check_release(a, ttl_seconds=36000, now=later).ok


def test_release_refused_one_shot_after_execution():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p6"))
    a = approve(store, "p6", approver="n")
    a["status"] = "executed"                 # one-shot: cannot re-release
    assert not check_release(a).ok


def test_reject():
    store = InMemoryStore()
    propose(store, build_plan(plan_id="p7"))
    r = reject(store, "p7", approver="n", reasoning="no")
    assert r["status"] == "rejected"
    assert not check_release(r).ok


def test_filestore_roundtrip(tmp_path):
    store = FileStore(tmp_path)
    propose(store, build_plan(plan_id="pf"))
    approve(store, "pf", approver="n")
    reloaded = store.get("pf")
    assert reloaded["status"] == "approved"
    assert check_release(reloaded).ok
    assert [p["plan_id"] for p in store.list()] == ["pf"]


def test_filestore_rejects_unsafe_id(tmp_path):
    store = FileStore(tmp_path)
    with pytest.raises(ValueError):
        store.get("../etc/passwd")
