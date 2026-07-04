# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Executor tests — the full gated run: re-validate, release gate, per-stage preconditions
(fail-closed), dispatch, verify, forward-only halt, audit chain."""
from conftest import FakeExecutor, FakeProbe, build_plan

from interlock.approval import InMemoryStore, approve, propose
from interlock.audit import InMemoryAuditSink, verify_chain
from interlock.executor import execute_plan


def _approved(plan):
    store = InMemoryStore()
    propose(store, plan)
    return approve(store, plan["plan_id"], approver="nathan")


def _two_stage_plan():
    # s1 read (no pre/rollback), s2 mutating with precondition + verify
    return build_plan(stages=[
        {"id": "s1", "action": "status_read", "params": {}},
        {"id": "s2", "action": "change_thing", "params": {"replicas": "3"},
         "target": {"kind": "service", "id": "web"},
         "preconditions": [{"check": "running", "expect": {"op": "equals", "value": "true"}}],
         "verify": [{"check": "replicas", "expect": {"op": "at_least", "value": "3"}}],
         "rollback": {"irreversible": True, "justification": "demo"}},
    ])


def test_happy_path_executes_and_audits(demo_policy):
    plan = _approved(_two_stage_plan())
    ex, pr, au = FakeExecutor(), FakeProbe({"running": True, "replicas": 3}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "executed", res.as_dict()
    assert [c.id for c in res.committed] == ["s1", "s2"]
    assert ("change_thing", {"replicas": "3"}, {"kind": "service", "id": "web"}) in ex.calls
    ok, detail = verify_chain(au.entries())
    assert ok, detail


def test_precondition_halts_before_dispatch(demo_policy):
    plan = _approved(_two_stage_plan())
    ex, pr, au = FakeExecutor(), FakeProbe({"running": False, "replicas": 3}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "halted"
    assert res.halted_stage.id == "s2" and res.halted_stage.status == "halted-precondition"
    # s2's mutating action was NEVER dispatched (only s1's read ran)
    assert all(c[0] != "change_thing" for c in ex.calls)
    assert [c.id for c in res.committed] == ["s1"]     # forward-only: s1 preserved


def test_unprobeable_precondition_fails_closed(demo_policy):
    plan = _approved(_two_stage_plan())
    ex, pr, au = FakeExecutor(), FakeProbe(unprobeable={"running"}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "halted" and res.halted_stage.status == "halted-precondition"


def test_execute_failure_halts(demo_policy):
    plan = _approved(_two_stage_plan())
    ex = FakeExecutor(fail={"change_thing"})
    pr, au = FakeProbe({"running": True, "replicas": 3}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "halted" and res.halted_stage.status == "halted-execute"


def test_verify_failure_halts(demo_policy):
    plan = _approved(_two_stage_plan())
    # precondition holds, dispatch ok, but the post-verify observes only 1 replica
    ex, pr, au = FakeExecutor(), FakeProbe({"running": True, "replicas": 1}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "halted" and res.halted_stage.status == "halted-verify"


def test_unapproved_plan_rejected(demo_policy):
    plan = build_plan()                        # status draft, no approval
    ex, pr, au = FakeExecutor(), FakeProbe(), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "rejected" and not ex.calls


def test_post_approval_tamper_rejected(demo_policy):
    plan = _approved(_two_stage_plan())
    plan["body"]["stages"][1]["params"]["replicas"] = "999"   # edit after approval, no rehash
    ex, pr, au = FakeExecutor(), FakeProbe({"running": True, "replicas": 999}), InMemoryAuditSink()
    res = execute_plan(plan, policy=demo_policy, executor=ex, prober=pr, audit=au)
    assert res.status == "rejected" and not ex.calls    # I2 hash mismatch -> never runs
