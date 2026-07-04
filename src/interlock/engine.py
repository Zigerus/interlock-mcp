# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The Interlock engine — one object that wires policy + store + adapters + audit into the
propose -> countersign -> execute -> verify lifecycle.

This is the reusable heart both surfaces sit on: the MCP server (agent-facing:
propose/get/list/execute) and the CLI (human-facing: approve/reject/verify-audit). It has
no MCP or CLI dependency, so it is fully unit-testable on its own.

Principle enforced here: the **proposer and the approver are different surfaces**. The
engine exposes ``approve``/``reject`` too, but the agent-facing MCP server deliberately
does NOT expose them — approval is a human action on a separate channel. Nothing the
proposing agent can call flips a plan to approved.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from .approval import PlanStore, approve as _approve, propose as _propose, reject as _reject
from .audit import AuditSink
from .executor import ExecutorAdapter, ExecutionResult, execute_plan
from .hashing import plan_hash_from_body
from .policy import Policy
from .preconditions import ProbeAdapter
from .schema import SCHEMA_VERSION
from .validate import validate

__all__ = ["Interlock", "ProposeResult"]


@dataclass
class ProposeResult:
    accepted: bool
    plan_id: str | None
    status: str
    validation: dict


class Interlock:
    def __init__(self, *, policy: Policy, store: PlanStore, executor: ExecutorAdapter,
                 prober: ProbeAdapter, audit: AuditSink, ttl_seconds: int | None = None) -> None:
        self.policy = policy
        self.store = store
        self.executor = executor
        self.prober = prober
        self.audit = audit
        self.ttl_seconds = ttl_seconds

    # --- agent-facing ---------------------------------------------------------
    def propose(self, body: dict, *, plan_id: str | None = None) -> ProposeResult:
        """Validate a plan BODY, and if it is approvable, record it as ``proposed`` and
        return its id. An unapprovable body is NOT stored — its validation errors come
        back so the agent can fix and retry. The server computes the hash; the agent
        never has to."""
        pid = plan_id or str(uuid.uuid4())
        plan = {
            "schema_version": SCHEMA_VERSION,
            "plan_id": pid,
            "plan_hash": plan_hash_from_body(body),
            "status": "draft",
            "body": body,
        }
        v = validate(plan, self.policy)
        if not v.approvable:
            self.audit.record({"kind": "propose-rejected", "plan_id": pid,
                               "reason": "not approvable", "invariants": v.as_dict()["invariants"]})
            return ProposeResult(False, None, "rejected", v.as_dict())
        self._propose_validated(plan)
        self.audit.record({"kind": "proposed", "plan_id": pid, "plan_hash": plan["plan_hash"],
                           "intent": body.get("intent")})
        return ProposeResult(True, pid, "proposed", v.as_dict())

    def _propose_validated(self, plan: dict) -> dict:
        return _propose(self.store, plan)

    def get(self, plan_id: str) -> dict | None:
        return self.store.get(plan_id)

    def list(self, status: str | None = None) -> list[dict]:
        plans = self.store.list()
        return [p for p in plans if status is None or p.get("status") == status]

    def execute(self, plan_id: str) -> ExecutionResult:
        """Run an approved plan through the gated executor and persist a TERMINAL outcome.

        Only ``executed`` / ``halted`` are persisted (they end the plan's life; one-shot
        follows because the release gate then refuses the non-approved status). A
        ``rejected`` result means the gate refused this attempt (not approved, expired,
        or body-tampered) — that is NOT a human rejection and must not mutate the plan,
        so the plan stays exactly as it was and can still be approved / retried."""
        plan = self.store.get(plan_id)
        if plan is None:
            return ExecutionResult(status="rejected", reason=f"no such plan {plan_id!r}")
        result = execute_plan(plan, policy=self.policy, executor=self.executor,
                              prober=self.prober, audit=self.audit, ttl_seconds=self.ttl_seconds)
        if result.status in ("executed", "halted"):
            plan["status"] = result.status
            plan["execution_result"] = result.as_dict()
            self.store.put(plan)
        return result

    # --- human-facing (NOT exposed on the agent MCP surface) ------------------
    def approve(self, plan_id: str, *, approver: str, reasoning: str = "") -> dict:
        p = _approve(self.store, plan_id, approver=approver, reasoning=reasoning)
        self.audit.record({"kind": "approved", "plan_id": plan_id, "approved_by": approver,
                           "plan_hash": p.get("plan_hash")})
        return p

    def reject(self, plan_id: str, *, approver: str, reasoning: str = "") -> dict:
        p = _reject(self.store, plan_id, approver=approver, reasoning=reasoning)
        self.audit.record({"kind": "rejected", "plan_id": plan_id, "rejected_by": approver})
        return p
