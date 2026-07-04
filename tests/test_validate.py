# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Validator tests — the valid plan passes all 7 invariants; each invariant fails in
isolation (nothing else regresses)."""
from conftest import build_plan, rehash

from interlock.validate import validate


def _inv(res, i):
    return next(x for x in res.invariants if x.id == i)


def assert_only_fails(res, i):
    assert not _inv(res, i).ok, f"expected inv{i} to fail: {_inv(res, i).detail}"
    others = [x for x in res.invariants if x.id != i and not x.ok]
    assert not others, f"other invariants also failed: {[(x.id, x.detail) for x in others]}"
    assert not res.approvable


# --- happy path ---------------------------------------------------------------
def test_valid_plan_approvable(demo_policy):
    res = validate(build_plan(), demo_policy)
    assert res.approvable, res.as_dict()
    assert res.verdict == "pass"
    assert len(res.invariants) == 7
    assert res.plan_hash_recomputed == res.plan_hash_declared


def test_read_only_plan_needs_no_rollback_or_preconditions(demo_policy):
    plan = build_plan(stages=[{"id": "s1", "action": "status_read", "params": {}}])
    res = validate(plan, demo_policy)
    assert res.approvable, res.as_dict()


# --- I1 schema ----------------------------------------------------------------
def test_i1_schema_extra_field(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["bogus"] = 1
    res = validate(rehash(plan), demo_policy)
    assert not res.schema_valid
    assert_only_fails(res, 1)


def test_i1_bad_precondition_op(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["preconditions"][0]["expect"]["op"] = "roughly"
    res = validate(rehash(plan), demo_policy)
    assert not res.schema_valid  # enum violation
    assert_only_fails(res, 1)


# --- I2 hash ------------------------------------------------------------------
def test_i2_hash_mismatch(demo_policy):
    plan = build_plan()
    plan["plan_hash"] = "0" * 64  # declared != recomputed
    res = validate(plan, demo_policy)
    assert_only_fails(res, 2)


def test_i2_post_approval_body_edit_voids_hash(demo_policy):
    # edit the body WITHOUT rehashing -> the approval binding breaks (tamper-evidence)
    plan = build_plan()
    plan["body"]["stages"][0]["params"]["replicas"] = "999"
    res = validate(plan, demo_policy)
    assert_only_fails(res, 2)


# --- I3 ids + known actions ---------------------------------------------------
def test_i3_duplicate_ids(demo_policy):
    s = {"id": "dup", "action": "status_read", "params": {}}
    res = validate(build_plan(stages=[dict(s), dict(s)]), demo_policy)
    assert_only_fails(res, 3)


def test_i3_unknown_action_rejected(demo_policy):
    plan = build_plan(stages=[{"id": "s1", "action": "totally_unknown", "params": {}}])
    res = validate(plan, demo_policy)
    assert_only_fails(res, 3)


def test_i3_unknown_action_allowed_when_policy_read(make_plan):
    from interlock.policy import Policy
    p = Policy(unknown_action="read")
    plan = make_plan(stages=[{"id": "s1", "action": "whatever", "params": {}}])
    res = validate(plan, p)
    assert res.approvable, res.as_dict()


# --- I4 rollback --------------------------------------------------------------
def test_i4_mutating_without_rollback(demo_policy):
    plan = build_plan()
    del plan["body"]["stages"][0]["rollback"]
    res = validate(rehash(plan), demo_policy)
    assert_only_fails(res, 4)


def test_i4_irreversible_marker_is_valid_rollback(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["rollback"] = {"irreversible": True, "justification": "no undo"}
    res = validate(rehash(plan), demo_policy)
    assert res.approvable, res.as_dict()


# --- I5 preconditions ---------------------------------------------------------
def test_i5_mutating_without_preconditions(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["preconditions"] = []
    res = validate(rehash(plan), demo_policy)
    assert_only_fails(res, 5)


def test_i5_waived_by_policy(make_plan):
    from interlock.policy import Policy, registry
    p = Policy(action_registry=registry(mutating=["change_thing"]),
               require_preconditions_for_mutating=False)
    plan = make_plan(stages=[{"id": "s1", "action": "change_thing", "params": {},
                              "rollback": {"irreversible": True, "justification": "x"}}])
    res = validate(plan, p)
    assert res.approvable, res.as_dict()


# --- I6 forbidden -------------------------------------------------------------
def test_i6_forbidden_action(demo_policy):
    # 'nuke' must be KNOWN (else I3 unknown-action fires); register it so only I6 fails.
    from interlock.policy import ActionSpec
    demo_policy.action_registry["nuke"] = ActionSpec(mutating=True)
    plan = build_plan(stages=[{"id": "s1", "action": "nuke", "params": {},
                               "preconditions": [{"check": "x", "expect": {"op": "equals", "value": "1"}}],
                               "rollback": {"irreversible": True, "justification": "x"}}])
    res = validate(plan, demo_policy)
    assert_only_fails(res, 6)


def test_i6_forbidden_target(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["target"] = {"kind": "vm", "id": "105"}
    res = validate(rehash(plan), demo_policy)
    assert_only_fails(res, 6)


# --- I7 secrets ---------------------------------------------------------------
def test_i7_secret_in_params(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["params"]["token"] = "ghp_" + "B" * 24
    res = validate(rehash(plan), demo_policy)
    assert_only_fails(res, 7)


def test_i7_digest_is_not_a_secret(demo_policy):
    plan = build_plan()
    plan["body"]["stages"][0]["params"]["image"] = "repo/img@sha256:" + "a" * 64
    res = validate(rehash(plan), demo_policy)
    assert res.approvable, res.as_dict()
