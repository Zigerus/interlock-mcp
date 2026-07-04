# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The staged executor — the only place a plan actually touches the world.

It runs an APPROVED plan one stage at a time, and at every step it distrusts:
  1. Re-validate the plan under policy + consult the release gate (approved, in-TTL,
     body-hash still matches the approval). A plan mutated after approval never runs.
  2. Per stage, BEFORE dispatch, re-check the stage's ``preconditions`` against LIVE
     ground truth via the probe adapter. Fail-closed: an unmet or unprobeable required
     precondition HALTS with nothing dispatched.
  3. Dispatch the action through the executor adapter (the sole side-effecting call).
  4. AFTER dispatch, check the stage's ``verify`` post-conditions. A failed verify HALTS.
  5. On ANY halt: forward-only. No automatic rollback — Interlock records what committed
     and stops; remediation is a NEW plan. Every step is written to the audit chain.

Executors and probes are injected adapters; this module is pure orchestration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .approval import ReleaseDecision, check_release
from .audit import AuditSink
from .policy import Policy
from .preconditions import ProbeAdapter, evaluate_preconditions
from .validate import validate

__all__ = ["ExecResult", "ExecutorAdapter", "StageOutcome", "ExecutionResult", "execute_plan"]


@dataclass
class ExecResult:
    ok: bool
    detail: str = ""


@runtime_checkable
class ExecutorAdapter(Protocol):
    def execute(self, action: str, params: dict, target: dict | None) -> ExecResult:
        """Perform ONE action. The only side-effecting call in the whole system."""
        ...


@dataclass
class StageOutcome:
    id: str
    action: str
    status: str            # committed | halted-precondition | halted-execute | halted-verify
    detail: str = ""


@dataclass
class ExecutionResult:
    status: str            # executed | halted | rejected
    committed: list[StageOutcome] = field(default_factory=list)
    halted_stage: StageOutcome | None = None
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "committed": [s.__dict__ for s in self.committed],
            "halted_stage": self.halted_stage.__dict__ if self.halted_stage else None,
            "reason": self.reason,
        }


def execute_plan(
    plan: dict,
    *,
    policy: Policy,
    executor: ExecutorAdapter,
    prober: ProbeAdapter,
    audit: AuditSink,
    ttl_seconds: int | None = None,
) -> ExecutionResult:
    """Execute an approved plan. Returns a structured result; never raises on a stage
    failure (it halts + audits). Raises only on a caller error (e.g. bad adapter type)."""
    plan_id = plan.get("plan_id")

    # Gate 1: re-validate under policy. A plan that isn't approvable NOW must not run,
    # even if it was approved earlier (policy may have tightened; body may be malformed).
    v = validate(plan, policy)
    if not v.approvable:
        reason = "re-validation failed: " + "; ".join(
            f"I{i.id} {i.name}: {i.detail}" for i in v.invariants if not i.ok) or "not approvable"
        audit.record({"kind": "preexec-reject", "plan_id": plan_id, "reason": reason})
        return ExecutionResult(status="rejected", reason=reason)

    # Gate 2: the release gate (approved, in-TTL, hash still bound to the approval).
    rel: ReleaseDecision = check_release(plan, ttl_seconds=ttl_seconds)
    if not rel.ok:
        audit.record({"kind": "release-refused", "plan_id": plan_id, "reason": rel.reason})
        return ExecutionResult(status="rejected", reason=rel.reason)

    audit.record({"kind": "execution-start", "plan_id": plan_id,
                  "plan_hash": plan.get("plan_hash"),
                  "approved_by": (plan.get("approval") or {}).get("approved_by")})

    committed: list[StageOutcome] = []
    stages = plan["body"]["stages"]
    for idx, stage in enumerate(stages):
        sid, action = stage.get("id"), stage.get("action")
        target = stage.get("target")

        # Pre-dispatch: preconditions vs. LIVE state (fail-closed).
        pre = evaluate_preconditions(stage.get("preconditions") or [], prober)
        if not pre.holds:
            outcome = StageOutcome(sid, action, "halted-precondition",
                                   f"preconditions not satisfied: {pre.failures}")
            audit.record({"kind": "halt", "plan_id": plan_id, "stage": sid, "index": idx,
                          "failure": "precondition", "detail": outcome.detail,
                          "committed": [c.id for c in committed]})
            return ExecutionResult(status="halted", committed=committed, halted_stage=outcome,
                                   reason=outcome.detail)

        # Dispatch (the one side-effecting call).
        result = executor.execute(action, stage.get("params") or {}, target)
        if not isinstance(result, ExecResult) or not result.ok:
            det = result.detail if isinstance(result, ExecResult) else "adapter returned non-ExecResult"
            outcome = StageOutcome(sid, action, "halted-execute", f"dispatch failed: {det}")
            audit.record({"kind": "halt", "plan_id": plan_id, "stage": sid, "index": idx,
                          "failure": "execute", "detail": outcome.detail,
                          "committed": [c.id for c in committed]})
            return ExecutionResult(status="halted", committed=committed, halted_stage=outcome,
                                   reason=outcome.detail)

        # Post-dispatch: verify the intended end-state (if declared).
        post = evaluate_preconditions(stage.get("verify") or [], prober)
        if not post.holds:
            outcome = StageOutcome(sid, action, "halted-verify",
                                   f"post-execution verify failed: {post.failures}")
            audit.record({"kind": "halt", "plan_id": plan_id, "stage": sid, "index": idx,
                          "failure": "verify", "detail": outcome.detail,
                          "committed": [c.id for c in committed]})
            return ExecutionResult(status="halted", committed=committed, halted_stage=outcome,
                                   reason=outcome.detail)

        outcome = StageOutcome(sid, action, "committed", result.detail)
        committed.append(outcome)
        audit.record({"kind": "stage-committed", "plan_id": plan_id, "stage": sid, "index": idx})

    audit.record({"kind": "execution-complete", "plan_id": plan_id,
                  "committed": [c.id for c in committed]})
    return ExecutionResult(status="executed", committed=committed)
