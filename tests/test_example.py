# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The shipped filesystem example must actually work (it's the front-page demo)."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "filesystem_demo", Path(__file__).resolve().parent.parent / "examples" / "filesystem_demo.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


def test_filesystem_demo_full_loop(tmp_path):
    s = demo.run(str(tmp_path / "hello.txt"))
    assert s["accepted"] is True
    assert s["pre_approval_status"] == "rejected"   # unapproved plan is refused
    assert s["final_status"] == "executed"
    assert s["file_exists"] is True
    assert s["audit_chain_ok"] is True


def test_demo_server_builds():
    # the agent MCP surface constructs cleanly over the demo engine
    from interlock.server import build_server
    srv = build_server(demo.build_engine())
    assert srv is not None
