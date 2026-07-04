# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Shared test fixtures: a demo policy, a plan builder, and a fake probe adapter."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from interlock.hashing import plan_hash_from_body          # noqa: E402
from interlock.policy import Policy, registry               # noqa: E402
from interlock.preconditions import ProbeResult             # noqa: E402
from interlock.schema import SCHEMA_VERSION                 # noqa: E402


@pytest.fixture
def demo_policy() -> Policy:
    return Policy(
        action_registry=registry(
            read_only=["status_read"],
            mutating=["change_thing", "remove_thing"],
            creating=["create_thing"],
        ),
        forbidden_actions=frozenset({"nuke"}),
        forbidden_targets=({"kind": "vm", "id": "105"}, {"kind": "gpu"}),
    )


def _mutating_stage() -> dict:
    return {
        "id": "s1",
        "action": "change_thing",
        "target": {"kind": "service", "id": "web"},
        "params": {"replicas": "3"},
        "preconditions": [
            {"check": "resource_running", "probe": {"id": "web"},
             "expect": {"op": "equals", "value": "true"}},
        ],
        "rollback": {"action": "change_thing", "target": {"kind": "service", "id": "web"},
                     "params": {"replicas": "1"}},
    }


def build_plan(stages=None, *, intent="demo change", plan_id="11111111-1111-4111-8111-111111111111",
               status="draft") -> dict:
    """A schema-valid, correctly-hashed plan. Pass custom stages to exercise invariants."""
    body = {"intent": intent, "stages": copy.deepcopy(stages if stages is not None else [_mutating_stage()])}
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_id": plan_id,
        "plan_hash": plan_hash_from_body(body),
        "status": status,
        "body": body,
    }


def rehash(plan: dict) -> dict:
    """Recompute plan_hash after mutating body (so only the intended invariant fails)."""
    plan["plan_hash"] = plan_hash_from_body(plan["body"])
    return plan


@pytest.fixture
def make_plan():
    return build_plan


@pytest.fixture
def rehash_plan():
    return rehash


@pytest.fixture
def mutating_stage():
    return _mutating_stage


class FakeProbe:
    """A probe adapter driven by a dict of {check: observed} plus an 'unprobeable' set."""
    def __init__(self, observations: dict | None = None, unprobeable: set | None = None):
        self.observations = observations or {}
        self.unprobeable = unprobeable or set()

    def probe(self, check, probe):
        if check in self.unprobeable:
            return ProbeResult(probeable=False, detail="no probe")
        if check in self.observations:
            return ProbeResult(probeable=True, observed=self.observations[check])
        return ProbeResult(probeable=False, detail="unknown check")


@pytest.fixture
def fake_probe():
    return FakeProbe
