# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The approval gate — hash-bound, one-shot, time-boxed human countersignature.

An approval in Interlock is not "the human clicked yes." It is a binding to the *exact
bytes* of a plan: at approval time the gate captures ``(schema_version, plan_hash)``, and
at execute time it re-derives the hash from the plan body and refuses to run unless it
still matches. So:

  * editing the body after approval **voids** the approval (tamper-evidence, invariant 2),
  * an approval is **one-shot** — a plan that has executed cannot be re-released,
  * an approval **expires** — a stale yes does not fire hours later against drifted reality.

Plans live in a pluggable :class:`PlanStore` (in-memory for tests/embedding, JSON files
for a durable single-node deployment; bring your own for a database).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from .hashing import plan_hash_from_document

__all__ = ["PlanStore", "InMemoryStore", "FileStore", "Clock",
           "propose", "approve", "reject", "check_release", "ReleaseDecision"]

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


@runtime_checkable
class PlanStore(Protocol):
    def get(self, plan_id: str) -> dict | None: ...
    def put(self, plan: dict) -> None: ...
    def list(self) -> list[dict]: ...


class InMemoryStore:
    def __init__(self) -> None:
        self._d: dict[str, dict] = {}

    def get(self, plan_id: str) -> dict | None:
        p = self._d.get(plan_id)
        return json.loads(json.dumps(p)) if p is not None else None  # copy out

    def put(self, plan: dict) -> None:
        self._d[plan["plan_id"]] = json.loads(json.dumps(plan))       # copy in

    def list(self) -> list[dict]:
        return [json.loads(json.dumps(p)) for p in self._d.values()]


class FileStore:
    """One JSON file per plan under ``root`` (atomic writes). Durable, single-node."""
    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, plan_id: str) -> Path:
        if not plan_id or "/" in plan_id or plan_id in (".", ".."):
            raise ValueError(f"unsafe plan_id {plan_id!r}")
        return self.root / f"{plan_id}.json"

    def get(self, plan_id: str) -> dict | None:
        p = self._path(plan_id)
        return json.loads(p.read_text()) if p.exists() else None

    def put(self, plan: dict) -> None:
        p = self._path(plan["plan_id"])
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(plan, indent=2))
        os.replace(tmp, p)

    def list(self) -> list[dict]:
        return [json.loads(p.read_text()) for p in sorted(self.root.glob("*.json"))]


# --- lifecycle ----------------------------------------------------------------
def propose(store: PlanStore, plan: dict, *, now: Clock = _utcnow) -> dict:
    """Record a validated plan as ``proposed`` (awaiting approval). The CALLER must have
    validated it approvable first — proposing an invalid plan is a programming error."""
    p = dict(plan)
    p["status"] = "proposed"
    p["approval"] = None
    p["proposed_at"] = _iso(now())
    store.put(p)
    return p


def approve(store: PlanStore, plan_id: str, *, approver: str, reasoning: str = "",
            now: Clock = _utcnow) -> dict:
    """Countersign a proposed plan. Binds ``(schema_version, plan_hash)`` as they stand
    now. Raises ValueError if the plan is missing or not in ``proposed`` state."""
    p = store.get(plan_id)
    if p is None:
        raise ValueError(f"no such plan {plan_id!r}")
    if p.get("status") != "proposed":
        raise ValueError(f"plan {plan_id!r} is {p.get('status')!r}, not 'proposed'")
    p["status"] = "approved"
    p["approval"] = {
        "approved_by": approver,
        "reasoning": reasoning,
        "approved_at": _iso(now()),
        "binding": {"schema_version": p.get("schema_version"), "plan_hash": p.get("plan_hash")},
    }
    store.put(p)
    return p


def reject(store: PlanStore, plan_id: str, *, approver: str, reasoning: str = "",
           now: Clock = _utcnow) -> dict:
    p = store.get(plan_id)
    if p is None:
        raise ValueError(f"no such plan {plan_id!r}")
    if p.get("status") not in ("proposed", "approved"):
        raise ValueError(f"plan {plan_id!r} is {p.get('status')!r}; only proposed/approved may be rejected")
    p["status"] = "rejected"
    p["approval"] = {"rejected_by": approver, "reasoning": reasoning, "rejected_at": _iso(now())}
    store.put(p)
    return p


@dataclass
class ReleaseDecision:
    ok: bool
    reason: str = ""


def check_release(plan: dict, *, ttl_seconds: int | None = None, now: Clock = _utcnow) -> ReleaseDecision:
    """The gate the executor consults before running an approved plan. ALL must hold:
      * status == 'approved' (one-shot: executing/executed/rejected are refused),
      * within TTL (if set) of the approval time,
      * schema_version == the approved binding,
      * the body still hashes to the approved plan_hash (no post-approval edit).
    """
    if plan.get("status") != "approved":
        return ReleaseDecision(False, f"status is {plan.get('status')!r}, not 'approved'")
    approval = plan.get("approval") or {}
    binding = approval.get("binding") or {}
    if binding.get("schema_version") != plan.get("schema_version"):
        return ReleaseDecision(False, "schema_version differs from the approved binding")
    try:
        recomputed = plan_hash_from_document(plan)
    except Exception as e:  # noqa: BLE001
        return ReleaseDecision(False, f"cannot recompute hash: {e}")
    if recomputed != binding.get("plan_hash"):
        return ReleaseDecision(False, "body changed since approval (hash mismatch) — approval void")
    if ttl_seconds is not None:
        approved_at = approval.get("approved_at")
        try:
            when = datetime.fromisoformat(approved_at)
        except (TypeError, ValueError):
            return ReleaseDecision(False, "approval has no valid approved_at timestamp")
        age = (now() - when).total_seconds()
        if age > ttl_seconds:
            return ReleaseDecision(False, f"approval expired ({int(age)}s > {ttl_seconds}s TTL)")
    return ReleaseDecision(True)
