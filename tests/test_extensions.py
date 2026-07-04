# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Extension-seam tests — a consumer adds domain fields + custom invariants WITHOUT
forking the core. Everything here is FICTIONAL (an `approvals` array-of-objects, a
`change_window` object, an "sre must sign mutating stages" rule) — the package never
learns any real deployment's vocabulary. These prove the seam is a *seam*: declared
extras pass, undeclared fields still reject, extension fields are hashed, custom
invariants run in the same pass and fail-closed."""
import copy

import pytest
from conftest import build_plan, rehash

from interlock.policy import CustomInvariant, Policy, registry
from interlock.schema import SchemaExtension, plan_schema
from interlock.validate import validate

# --- a fictional deployment's extension (array-of-objects, like a real domain field) ----
APPROVALS_FIELD = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["team", "ref"],
        "additionalProperties": False,
        "properties": {"team": {"type": "string"}, "ref": {"type": "string"}},
    },
}
CHANGE_WINDOW_FIELD = {
    "type": "object",
    "required": ["opens", "closes"],
    "additionalProperties": False,
    "properties": {"opens": {"type": "string"}, "closes": {"type": "string"}},
}
EXT = SchemaExtension(
    stage_properties={"approvals": APPROVALS_FIELD},
    body_properties={"change_window": CHANGE_WINDOW_FIELD},
)


def _requires_sre_approval(plan, policy):
    bad = [s.get("id") for s in plan["body"]["stages"]
           if policy.is_mutating(s.get("action"))
           and not any(a.get("team") == "sre" for a in (s.get("approvals") or []))]
    return (not bad, f"mutating stages without an sre approval: {bad}" if bad else "")


SRE_INV = CustomInvariant("mutating-needs-sre-approval", _requires_sre_approval)


def ext_policy(*, custom_invariants=(SRE_INV,)) -> Policy:
    return Policy(
        action_registry=registry(read_only=["status_read"], mutating=["change_thing"]),
        schema_extension=EXT,
        custom_invariants=custom_invariants,
    )


def ext_plan(*, sre=True, extra_stage_field=None, extra_body_field=None) -> dict:
    """A schema-valid, correctly-hashed plan carrying the fictional extension fields."""
    stage = {
        "id": "s1", "action": "change_thing",
        "target": {"kind": "service", "id": "web"},
        "params": {"replicas": "3"},
        "preconditions": [{"check": "up", "probe": {"id": "web"},
                           "expect": {"op": "equals", "value": "true"}}],
        "rollback": {"action": "change_thing", "target": {"kind": "service", "id": "web"},
                     "params": {"replicas": "1"}},
        "approvals": [{"team": "sre", "ref": "CHG-1"}] if sre else [{"team": "dev", "ref": "CHG-1"}],
    }
    if extra_stage_field:
        stage.update(extra_stage_field)
    plan = build_plan(stages=[stage])
    plan["body"]["change_window"] = {"opens": "01:00", "closes": "02:00"}
    if extra_body_field:
        plan["body"].update(extra_body_field)
    return rehash(plan)


def _by_name(res, name):
    return next(x for x in res.invariants if x.name == name)


# --- schema extension: declared fields pass -----------------------------------
def test_declared_extension_fields_pass():
    res = validate(ext_plan(), ext_policy())
    assert res.approvable, res.as_dict()
    assert res.schema_valid


# --- schema extension: the SAFETY property — undeclared fields STILL reject ----
def test_undeclared_stage_field_rejects_even_with_extension_active():
    res = validate(ext_plan(extra_stage_field={"bogus": 1}), ext_policy())
    assert not res.schema_valid, "an undeclared stage field must still fail I1"
    assert not res.approvable
    assert not _by_name(res, "schema-valid").ok


def test_undeclared_body_field_rejects_even_with_extension_active():
    res = validate(ext_plan(extra_body_field={"nope": 1}), ext_policy())
    assert not res.schema_valid, "an undeclared body field must still fail I1"
    assert not res.approvable


# --- schema extension: extra fields are inside body -> they are HASHED ---------
def test_extension_field_participates_in_hash():
    plan = ext_plan()
    # mutate the extension field WITHOUT rehashing -> the approval binding must break.
    plan["body"]["stages"][0]["approvals"][0]["ref"] = "CHG-TAMPERED"
    res = validate(plan, ext_policy())
    assert not _by_name(res, "plan_hash-recomputes").ok, "extension field must be in the hashed body"
    assert not res.approvable


# --- schema extension: no cross-contamination of the shared module schema ------
def test_base_schema_not_mutated_by_extension():
    # run an extended validation, THEN validate an `approvals`-carrying plan under a policy
    # with NO extension — it must reject, proving apply() deep-copied and left the base clean.
    validate(ext_plan(), ext_policy())
    base_policy = Policy(action_registry=registry(read_only=["status_read"], mutating=["change_thing"]))
    res = validate(ext_plan(), base_policy)
    assert not res.schema_valid, "base schema leaked the extension — deepcopy failed"
    # and the module-level schema object still has no 'approvals' at stage level
    stage_props = plan_schema()["properties"]["body"]["properties"]["stages"]["items"]["properties"]
    assert "approvals" not in stage_props


# --- schema extension: collision guard ----------------------------------------
def test_extension_cannot_redefine_a_builtin_field():
    with pytest.raises(ValueError, match="already exists"):
        SchemaExtension(stage_properties={"action": {"type": "string"}}).apply(plan_schema())


# --- custom invariant: fails when violated, in isolation ----------------------
def test_custom_invariant_fails_when_violated():
    res = validate(ext_plan(sre=False), ext_policy())
    ci = _by_name(res, "mutating-needs-sre-approval")
    assert not ci.ok
    assert ci.id == 8  # numbered after the built-in 7
    # nothing else regressed — the built-in seven are all green
    builtin_fails = [x for x in res.invariants if x.id <= 7 and not x.ok]
    assert not builtin_fails, builtin_fails
    assert not res.approvable


def test_custom_invariant_passes_when_satisfied():
    res = validate(ext_plan(sre=True), ext_policy())
    assert _by_name(res, "mutating-needs-sre-approval").ok
    assert res.approvable, res.as_dict()


# --- custom invariant: fail-closed on raise (validate never raises) -----------
def test_custom_invariant_that_raises_is_fail_closed():
    def boom(plan, policy):
        raise KeyError("stages")  # a buggy check on a malformed plan
    pol = ext_policy(custom_invariants=(CustomInvariant("explodes", boom),))
    res = validate(ext_plan(), pol)  # must NOT raise
    bad = _by_name(res, "explodes")
    assert not bad.ok
    assert "raised" in bad.detail
    assert not res.approvable


# --- custom invariants: multiple, numbered I8, I9 -----------------------------
def test_multiple_custom_invariants_are_numbered_sequentially():
    second = CustomInvariant("always-ok", lambda plan, policy: True)  # bare-bool return supported
    res = validate(ext_plan(sre=True), ext_policy(custom_invariants=(SRE_INV, second)))
    ids = {x.name: x.id for x in res.invariants}
    assert ids["mutating-needs-sre-approval"] == 8
    assert ids["always-ok"] == 9
    assert res.approvable, res.as_dict()


# --- no-extension path is unchanged (base behavior preserved) -----------------
def test_no_extension_policy_still_seven_invariants():
    base_policy = Policy(action_registry=registry(read_only=["status_read"], mutating=["change_thing"]))
    plan = build_plan(stages=[{"id": "s1", "action": "status_read", "params": {}}])
    res = validate(plan, base_policy)
    assert len(res.invariants) == 7
    assert res.approvable, res.as_dict()
