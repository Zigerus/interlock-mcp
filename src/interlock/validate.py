# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Deterministic plan validator — schema + universal invariants + hash recompute.

Pure and side-effect-free: same plan + same policy -> same verdict, on any machine. This
is the gate a plan must pass before it can be *proposed* for approval; a plan that is not
``approvable`` never reaches a human, and (belt and suspenders) is re-validated at execute
time so a body mutated after approval is caught.

The seven invariants are universal (they hold for any domain); everything domain-specific
they need — which actions mutate, which targets are forbidden, what a secret looks like —
comes from the :class:`~interlock.policy.Policy`, never from this module.

  I1  schema-valid (Draft 2020-12)
  I2  plan_hash recomputes to the declared value (approval binds exact bytes)
  I3  stage ids unique AND every action is known to the policy (per unknown_action)
  I4  every mutating stage has a valid rollback
  I5  every mutating stage has non-empty preconditions (if policy requires)
  I6  no forbidden action or forbidden target (stage or rollback)
  I7  no plaintext secret in params / preconditions / target

Two optional extension seams, both carried on the Policy so propose and execute validate
under identical rules (see :mod:`interlock.policy`):
  * ``policy.schema_extension`` — extra plan fields merged into the schema for I1
    (``additionalProperties: False`` stays in force; an undeclared field still fails I1).
  * ``policy.custom_invariants`` — deployment-specific rules run in the same pass, numbered
    I8, I9, … after the built-ins, each wrapped fail-closed (a raising check becomes a failure,
    never an exception out of ``validate()``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import jsonschema

from .hashing import plan_hash_from_document
from .policy import Policy
from .schema import plan_schema

__all__ = ["InvariantResult", "ValidationResult", "validate"]


@dataclass
class InvariantResult:
    id: int
    name: str
    ok: bool
    detail: str = ""


@dataclass
class ValidationResult:
    schema_valid: bool
    schema_errors: list[dict] = field(default_factory=list)
    invariants: list[InvariantResult] = field(default_factory=list)
    plan_hash_declared: str | None = None
    plan_hash_recomputed: str | None = None
    approvable: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "pass" if self.approvable else "fail"

    def as_dict(self) -> dict:
        return {
            "schema_valid": self.schema_valid,
            "schema_errors": self.schema_errors,
            "invariants": [i.__dict__ for i in self.invariants],
            "plan_hash_declared": self.plan_hash_declared,
            "plan_hash_recomputed": self.plan_hash_recomputed,
            "approvable": self.approvable,
            "verdict": self.verdict,
            "errors": self.errors,
        }


def _valid_rollback(rb: Any) -> bool:
    if not isinstance(rb, dict) or not rb:
        return False
    if rb.get("irreversible") is True and isinstance(rb.get("justification"), str) and rb["justification"]:
        return True
    return isinstance(rb.get("action"), str) and bool(rb["action"])


def _scan_secret(obj: Any, policy: Policy, hits: list[str]) -> None:
    if isinstance(obj, str):
        if policy.find_secret(obj):
            hits.append(obj[:60])
    elif isinstance(obj, dict):
        for v in obj.values():
            _scan_secret(v, policy, hits)
    elif isinstance(obj, list):
        for v in obj:
            _scan_secret(v, policy, hits)


def validate(plan: dict, policy: Policy) -> ValidationResult:
    """Validate ``plan`` under ``policy``. Never raises on a bad plan — returns a
    structured verdict (it raises only on a genuinely broken *schema*, which is a bug)."""
    res = ValidationResult(schema_valid=True)

    # I1 — structural schema (base schema, or the base with the deployment's declared
    # extra fields merged in — additionalProperties:False still bites undeclared fields).
    schema = plan_schema()
    if policy.schema_extension is not None:
        schema = policy.schema_extension.apply(schema)
    validator = jsonschema.Draft202012Validator(schema)
    errs = sorted(validator.iter_errors(plan), key=lambda e: list(e.path))
    if errs:
        res.schema_valid = False
        for e in errs[:25]:
            res.schema_errors.append({
                "path": "/".join(str(p) for p in e.path) or "(root)",
                "validator": e.validator,
                "message": e.message,
            })
    res.invariants.append(InvariantResult(1, "schema-valid", res.schema_valid,
                                          "" if res.schema_valid else f"{len(errs)} schema error(s)"))

    body = plan.get("body") if isinstance(plan, dict) else None
    stages = body.get("stages") if isinstance(body, dict) and isinstance(body.get("stages"), list) else []
    res.plan_hash_declared = plan.get("plan_hash") if isinstance(plan, dict) else None

    # I2 — hash recompute.
    ok2, detail2 = False, ""
    try:
        res.plan_hash_recomputed = plan_hash_from_document(plan)
        ok2 = res.plan_hash_recomputed == res.plan_hash_declared
        detail2 = "" if ok2 else f"declared={res.plan_hash_declared!r} recomputed={res.plan_hash_recomputed!r}"
    except Exception as e:  # noqa: BLE001
        detail2 = f"recompute failed: {type(e).__name__}: {e}"
    res.invariants.append(InvariantResult(2, "plan_hash-recomputes", ok2, detail2))

    # I3 — unique ids + known actions.
    ids = [s.get("id") for s in stages]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    unknown = sorted({s.get("action") for s in stages
                      if not policy.is_known(s.get("action"))}) if policy.unknown_action == "reject" else []
    ok3 = not dup and not unknown
    detail3 = "; ".join(filter(None, [
        f"duplicate stage ids: {dup}" if dup else "",
        f"unknown actions (policy=reject): {unknown}" if unknown else "",
    ]))
    res.invariants.append(InvariantResult(3, "unique-ids-and-known-actions", ok3, detail3))

    # I4 — mutating -> valid rollback.
    bad4 = [s.get("id") for s in stages
            if policy.is_mutating(s.get("action")) and not _valid_rollback(s.get("rollback"))]
    res.invariants.append(InvariantResult(4, "mutating-stage-has-rollback", not bad4,
                                          f"stages without valid rollback: {bad4}" if bad4 else ""))

    # I5 — mutating -> non-empty preconditions (if required).
    if policy.require_preconditions_for_mutating:
        bad5 = [s.get("id") for s in stages
                if policy.is_mutating(s.get("action"))
                and not (isinstance(s.get("preconditions"), list) and s.get("preconditions"))]
        res.invariants.append(InvariantResult(5, "mutating-stage-has-preconditions", not bad5,
                                              f"stages without preconditions: {bad5}" if bad5 else ""))
    else:
        res.invariants.append(InvariantResult(5, "mutating-stage-has-preconditions", True,
                                              "(not required by policy)"))

    # I6 — forbidden action / target (stage targets AND rollback compensating targets).
    forb: list[str] = []
    for s in stages:
        if policy.is_forbidden_action(s.get("action")):
            forb.append(f"{s.get('id')}: action {s.get('action')!r} forbidden")
        if policy.is_forbidden_target(s.get("target")):
            forb.append(f"{s.get('id')}: target {s.get('target')} forbidden")
        rb = s.get("rollback")
        if isinstance(rb, dict):
            if policy.is_forbidden_action(rb.get("action")):
                forb.append(f"{s.get('id')}: rollback action {rb.get('action')!r} forbidden")
            if policy.is_forbidden_target(rb.get("target")):
                forb.append(f"{s.get('id')}: rollback target {rb.get('target')} forbidden")
    res.invariants.append(InvariantResult(6, "no-forbidden-action-or-target", not forb, "; ".join(forb)))

    # I7 — no plaintext secrets in params / preconditions / target.
    hits: list[str] = []
    for s in stages:
        _scan_secret(s.get("params"), policy, hits)
        _scan_secret(s.get("preconditions"), policy, hits)
        _scan_secret(s.get("target"), policy, hits)
    res.invariants.append(InvariantResult(7, "no-plaintext-secrets", not hits,
                                          f"secret-shaped values: {hits}" if hits else ""))

    # I8+ — deployment-supplied custom invariants, run in the same pass and folded into
    # approvability. Each is wrapped fail-closed: a check that raises becomes a FAILED
    # invariant, never an exception out of validate() (which must never raise on a bad plan).
    next_id = 8
    for ci in policy.custom_invariants:
        try:
            r = ci.check(plan, policy)
            ok, detail = r if isinstance(r, tuple) else (bool(r), "")
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"custom invariant raised: {type(e).__name__}: {e}"
        res.invariants.append(InvariantResult(next_id, ci.name, bool(ok), "" if ok else str(detail)))
        next_id += 1

    res.approvable = res.schema_valid and all(i.ok for i in res.invariants)
    return res
