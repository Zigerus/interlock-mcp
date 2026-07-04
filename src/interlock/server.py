# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The agent-facing MCP server.

Exposes exactly the tools a *proposing agent* should have — and deliberately NOT
``approve``/``reject``. Approval is a human action on a separate channel (the
``interlock`` CLI or your own admin surface); nothing here can flip a plan to approved,
which is the whole point of the interlock.

Tools:
  * ``propose_plan(body)``   — validate a plan body under policy; if approvable, record it
    as *proposed* and return its id. The server computes the hash — the agent never does.
  * ``get_plan(plan_id)``    — the full plan document + its status.
  * ``list_plans(status?)``  — plans (optionally filtered by status).
  * ``execute_plan(plan_id)``— run an *approved* plan through the gated executor. On an
    unapproved plan this returns ``rejected`` — the gate, not the tool, enforces approval.

Construct with :func:`build_server`, passing your :class:`~interlock.engine.Interlock`
(policy + store + adapters + audit). ``main`` loads a config module named by
``INTERLOCK_CONFIG`` that must expose ``build() -> Interlock``.
"""
from __future__ import annotations

import importlib
import os

from mcp.server.fastmcp import FastMCP

from .engine import Interlock

__all__ = ["build_server", "main"]


def build_server(engine: Interlock, *, name: str = "interlock") -> FastMCP:
    mcp = FastMCP(name)

    @mcp.tool()
    def propose_plan(body: dict) -> dict:
        """Propose a change. `body` is an Interlock plan body: {intent, stages:[...]}.
        Returns {accepted, plan_id, status, validation}. If not accepted, `validation`
        lists the failing invariants — fix and re-propose. A proposed plan is HELD until
        a human countersigns it out-of-band; it does not execute on propose."""
        r = engine.propose(body)
        return {"accepted": r.accepted, "plan_id": r.plan_id, "status": r.status,
                "validation": r.validation}

    @mcp.tool()
    def get_plan(plan_id: str) -> dict:
        """Fetch a plan document (envelope + body + status + approval)."""
        p = engine.get(plan_id)
        return p if p is not None else {"error": f"no such plan {plan_id!r}"}

    @mcp.tool()
    def list_plans(status: str | None = None) -> dict:
        """List plans, optionally filtered by status
        (draft|proposed|approved|rejected|executing|executed|halted|expired)."""
        plans = engine.list(status)
        return {"count": len(plans),
                "plans": [{"plan_id": p.get("plan_id"), "status": p.get("status"),
                           "intent": (p.get("body") or {}).get("intent")} for p in plans]}

    @mcp.tool()
    def execute_plan(plan_id: str) -> dict:
        """Execute an APPROVED plan through the gated staged executor. Returns the
        execution result. If the plan is not approved (or the approval is expired / the
        body changed since approval), this returns status 'rejected' — approval is
        enforced by the gate, never by the caller."""
        return engine.execute(plan_id).as_dict()

    return mcp


def _load_engine() -> Interlock:
    mod_name = os.environ.get("INTERLOCK_CONFIG")
    if not mod_name:
        raise SystemExit(
            "set INTERLOCK_CONFIG to a module exposing build() -> Interlock "
            "(see examples/ for a template).")
    mod = importlib.import_module(mod_name)
    if not hasattr(mod, "build"):
        raise SystemExit(f"{mod_name} has no build() -> Interlock")
    return mod.build()


def main() -> None:
    """Console entrypoint (``interlock-mcp``). Runs the stdio MCP server built from the
    engine that ``INTERLOCK_CONFIG``'s ``build()`` returns."""
    build_server(_load_engine()).run()


if __name__ == "__main__":
    main()
