# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The human-facing CLI — the separate channel where countersigning happens.

Kept apart from the agent MCP surface on purpose: the agent proposes; a human reviews and
approves *here*. ``approve`` shows the exact plan and requires an explicit approver name,
so the countersignature is attributable.

Commands:
  interlock list [--status S]
  interlock show <plan_id>
  interlock approve <plan_id> --by NAME [--reason TEXT]
  interlock reject  <plan_id> --by NAME [--reason TEXT]
  interlock verify-audit <audit.jsonl>

Reads the same engine your server uses via ``INTERLOCK_CONFIG`` (module with
``build() -> Interlock``), so the CLI and server share one store + audit log.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

from .audit import verify_chain
from .engine import Interlock


def _engine() -> Interlock:
    mod_name = os.environ.get("INTERLOCK_CONFIG")
    if not mod_name:
        raise SystemExit("set INTERLOCK_CONFIG to a module exposing build() -> Interlock")
    return importlib.import_module(mod_name).build()


def _summary(p: dict) -> str:
    return f"{p.get('plan_id')}  [{p.get('status')}]  {(p.get('body') or {}).get('intent','')}"


def cmd_list(args) -> int:
    for p in _engine().list(args.status):
        print(_summary(p))
    return 0


def cmd_show(args) -> int:
    p = _engine().get(args.plan_id)
    if p is None:
        print(f"no such plan {args.plan_id!r}", file=sys.stderr)
        return 1
    print(json.dumps(p, indent=2))
    return 0


def cmd_approve(args) -> int:
    eng = _engine()
    p = eng.get(args.plan_id)
    if p is None:
        print(f"no such plan {args.plan_id!r}", file=sys.stderr)
        return 1
    # show the exact thing being countersigned before binding it
    print(json.dumps(p.get("body"), indent=2))
    print(f"\nplan_hash: {p.get('plan_hash')}  (this exact body is what you are approving)\n")
    try:
        eng.approve(args.plan_id, approver=args.by, reasoning=args.reason or "")
    except ValueError as e:
        print(f"cannot approve: {e}", file=sys.stderr)
        return 1
    print(f"APPROVED {args.plan_id} by {args.by}")
    return 0


def cmd_reject(args) -> int:
    try:
        _engine().reject(args.plan_id, approver=args.by, reasoning=args.reason or "")
    except ValueError as e:
        print(f"cannot reject: {e}", file=sys.stderr)
        return 1
    print(f"REJECTED {args.plan_id} by {args.by}")
    return 0


def cmd_verify_audit(args) -> int:
    with open(args.path) as f:
        entries = [json.loads(line) for line in f if line.strip()]
    ok, detail = verify_chain(entries)
    print(detail)
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="interlock", description="Interlock human review CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="list plans"); p.add_argument("--status"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("show", help="show a plan"); p.add_argument("plan_id"); p.set_defaults(fn=cmd_show)
    p = sub.add_parser("approve", help="countersign a proposed plan")
    p.add_argument("plan_id"); p.add_argument("--by", required=True); p.add_argument("--reason")
    p.set_defaults(fn=cmd_approve)
    p = sub.add_parser("reject", help="reject a plan")
    p.add_argument("plan_id"); p.add_argument("--by", required=True); p.add_argument("--reason")
    p.set_defaults(fn=cmd_reject)
    p = sub.add_parser("verify-audit", help="verify an audit-log hash chain")
    p.add_argument("path"); p.set_defaults(fn=cmd_verify_audit)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
