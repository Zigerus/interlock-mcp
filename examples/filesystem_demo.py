# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""A complete, dependency-free Interlock example: govern a filesystem change.

Runs the whole loop against a temp directory so anyone can execute it
(`python examples/filesystem_demo.py`) with no infrastructure:

    propose (write a file)  ->  human approves  ->  execute
      stage precondition: the target file does NOT already exist (live probe)
      dispatch:           write it
      verify:             the file now exists

It also shows the guarantees: an unapproved plan will not run, and editing the plan
body after approval voids the approval. This module is imported by tests/test_example.py.

The two adapters below are the ENTIRE integration surface — implement `execute` and
`probe` for your world and the governance core does the rest.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from interlock.adapters import ExecResult, ProbeResult          # noqa: E402
from interlock.approval import InMemoryStore                    # noqa: E402
from interlock.audit import InMemoryAuditSink, verify_chain     # noqa: E402
from interlock.engine import Interlock                          # noqa: E402
from interlock.policy import Policy, registry                   # noqa: E402


class FileExecutor:
    """ExecutorAdapter — the only side-effecting code. Writes a file for `write_file`."""
    def execute(self, action, params, target):
        if action != "write_file":
            return ExecResult(ok=False, detail=f"unknown action {action!r}")
        try:
            Path(params["path"]).write_text(params.get("content", ""))
            return ExecResult(ok=True, detail=f"wrote {params['path']}")
        except Exception as e:  # noqa: BLE001
            return ExecResult(ok=False, detail=str(e))


class FileProber:
    """ProbeAdapter — read-only. `file_exists` -> bool for the given path."""
    def probe(self, check, probe):
        if check != "file_exists":
            return ProbeResult(probeable=False, detail=f"no probe for {check!r}")
        return ProbeResult(probeable=True, observed=Path(probe["path"]).exists())


def build_engine() -> Interlock:
    policy = Policy(action_registry=registry(mutating=["write_file"]))
    return Interlock(policy=policy, store=InMemoryStore(),
                     executor=FileExecutor(), prober=FileProber(), audit=InMemoryAuditSink())


def plan_body(path: str) -> dict:
    return {
        "intent": f"create {path}",
        "stages": [{
            "id": "write",
            "action": "write_file",
            "params": {"path": path, "content": "hello from interlock\n"},
            "target": {"kind": "file", "id": path},
            # precondition: the file must NOT already exist before we write it
            "preconditions": [{"check": "file_exists", "probe": {"path": path},
                               "expect": {"op": "equals", "value": "false"}}],
            # verify: it DOES exist afterward
            "verify": [{"check": "file_exists", "probe": {"path": path},
                        "expect": {"op": "equals", "value": "true"}}],
            "rollback": {"action": "write_file", "params": {"path": path, "content": ""},
                         "target": {"kind": "file", "id": path}},
        }],
    }


def run(path: str) -> dict:
    """Drive the full loop; return a summary dict (used by the test)."""
    eng = build_engine()
    proposed = eng.propose(plan_body(path))

    # 1) an unapproved plan will NOT run
    pre_approval = eng.execute(proposed.plan_id).status

    # 2) a human countersigns, then it executes
    eng.approve(proposed.plan_id, approver="operator", reasoning="looks good")
    result = eng.execute(proposed.plan_id)

    chain_ok, _ = verify_chain(eng.audit.entries())
    return {
        "plan_id": proposed.plan_id,
        "accepted": proposed.accepted,
        "pre_approval_status": pre_approval,   # 'rejected' — the gate held
        "final_status": result.status,         # 'executed'
        "file_exists": Path(path).exists(),
        "audit_chain_ok": chain_ok,
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        summary = run(str(Path(d) / "hello.txt"))
    print("Interlock filesystem demo")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    ok = (summary["accepted"] and summary["pre_approval_status"] == "rejected"
          and summary["final_status"] == "executed" and summary["file_exists"]
          and summary["audit_chain_ok"])
    print("\nOK" if ok else "\nFAILED")
    sys.exit(0 if ok else 1)
