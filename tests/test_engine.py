# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Engine facade tests — the propose -> approve -> execute lifecycle end to end."""
from conftest import FakeExecutor, FakeProbe

from interlock.approval import InMemoryStore
from interlock.audit import InMemoryAuditSink, verify_chain
from interlock.engine import Interlock


def _engine(policy, *, fail=None, obs=None, unprobeable=None):
    return Interlock(
        policy=policy,
        store=InMemoryStore(),
        executor=FakeExecutor(fail=fail or set()),
        prober=FakeProbe(observations=obs or {}, unprobeable=unprobeable or set()),
        audit=InMemoryAuditSink(),
    )


def _body():
    return {"intent": "scale web", "stages": [
        {"id": "s1", "action": "change_thing", "params": {"replicas": "3"},
         "target": {"kind": "service", "id": "web"},
         "preconditions": [{"check": "running", "expect": {"op": "equals", "value": "true"}}],
         "rollback": {"irreversible": True, "justification": "demo"}},
    ]}


def test_propose_valid_is_held(demo_policy):
    eng = _engine(demo_policy)
    r = eng.propose(_body())
    assert r.accepted and r.status == "proposed"
    assert eng.get(r.plan_id)["status"] == "proposed"       # HELD, not executed


def test_propose_invalid_not_stored(demo_policy):
    eng = _engine(demo_policy)
    bad = {"intent": "x", "stages": [{"id": "s1", "action": "change_thing", "params": {}}]}  # no rollback/preconds
    r = eng.propose(bad)
    assert not r.accepted and r.plan_id is None
    assert eng.list() == []                                  # nothing stored


def test_full_lifecycle_execute(demo_policy):
    eng = _engine(demo_policy, obs={"running": True})
    pid = eng.propose(_body()).plan_id
    eng.approve(pid, approver="nathan", reasoning="ok")
    res = eng.execute(pid)
    assert res.status == "executed"
    assert eng.get(pid)["status"] == "executed"
    ok, detail = verify_chain(eng.audit.entries())
    assert ok, detail


def test_execute_without_approval_rejected(demo_policy):
    eng = _engine(demo_policy, obs={"running": True})
    pid = eng.propose(_body()).plan_id                        # proposed, not approved
    res = eng.execute(pid)
    assert res.status == "rejected"
    assert not eng.executor.calls                             # nothing ran


def test_one_shot_no_double_execute(demo_policy):
    eng = _engine(demo_policy, obs={"running": True})
    pid = eng.propose(_body()).plan_id
    eng.approve(pid, approver="n")
    assert eng.execute(pid).status == "executed"
    # second execute: plan is now 'executed', release gate refuses
    assert eng.execute(pid).status == "rejected"


def test_precondition_halt_persists(demo_policy):
    eng = _engine(demo_policy, obs={"running": False})
    pid = eng.propose(_body()).plan_id
    eng.approve(pid, approver="n")
    res = eng.execute(pid)
    assert res.status == "halted"
    assert eng.get(pid)["status"] == "halted"
