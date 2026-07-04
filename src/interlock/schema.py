# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""The generic Interlock plan schema (JSON Schema, Draft 2020-12).

Domain-agnostic by design. The core knows a plan is an ordered list of *stages*, each
with an opaque *action* (an adapter interprets it), an optional *target*, typed
*preconditions*, and a *rollback*. It does NOT know "docker", "kubernetes", or your
hosts — which actions mutate, which targets are forbidden, and what a secret looks like
are all supplied by a :class:`~interlock.policy.Policy` at validation time, never baked
into the schema.

Envelope vs. body:
  * ``body`` is the approval-bound content — it is what gets hashed (``plan_hash``).
  * Everything outside ``body`` (``schema_version``, ``plan_id``, ``plan_hash``,
    ``status``, ``approval``) is envelope: metadata the hash must NOT cover, because it
    changes across the plan's lifecycle while the approved intent stays fixed.

``schema_version`` binds *alongside* ``plan_hash`` (approval = the pair), so a schema
bump voids prior approvals exactly as a body change does.
"""
from __future__ import annotations

SCHEMA_VERSION = "1"

# Precondition comparison operators the core precondition engine understands.
PRECONDITION_OPS = ["equals", "not_equals", "at_least", "at_most", "contains"]

# Plan lifecycle states (envelope-only; not hashed).
PLAN_STATES = ["draft", "proposed", "approved", "rejected", "executing",
               "executed", "halted", "expired"]

_TARGET_SCHEMA = {
    "type": "object",
    "required": ["kind", "id"],
    "properties": {
        "kind": {"type": "string", "minLength": 1},
        "id": {"type": "string", "minLength": 1},
    },
    # extra target fields (host, region, ...) are adapter-specific — allowed.
    "additionalProperties": True,
}

_PRECONDITION_SCHEMA = {
    "type": "object",
    "required": ["check", "expect"],
    "additionalProperties": False,
    "properties": {
        "check": {"type": "string", "minLength": 1,
                  "description": "Check kind — the probe adapter must implement it."},
        "probe": {"type": "object",
                  "description": "What to probe (adapter-interpreted)."},
        "expect": {
            "type": "object",
            "required": ["op", "value"],
            "additionalProperties": False,
            "properties": {
                "op": {"enum": PRECONDITION_OPS},
                # value is a typed STRING on purpose: it keeps the plan_hash stable and
                # sidesteps the YAML 1.1 on/off->bool and numeric-coercion traps. The
                # engine parses it against the observed value per-op.
                "value": {"type": "string",
                          "description": "Typed STRING. Run-state: 'true'/'false'. Numeric: decimal string."},
            },
        },
        "note": {"type": "string"},
    },
}

_ROLLBACK_SCHEMA = {
    "oneOf": [
        {   # a concrete compensating stage
            "type": "object",
            "required": ["action"],
            "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "minLength": 1},
                "params": {"type": "object"},
                "target": _TARGET_SCHEMA,
            },
        },
        {   # an explicit irreversible marker (flags a human gate; still a VALID rollback)
            "type": "object",
            "required": ["irreversible", "justification"],
            "additionalProperties": False,
            "properties": {
                "irreversible": {"const": True},
                "justification": {"type": "string", "minLength": 1},
            },
        },
    ],
}

_STAGE_SCHEMA = {
    "type": "object",
    "required": ["id", "action"],
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "action": {"type": "string", "minLength": 1,
                   "description": "Opaque to the core; the Policy classifies it and an adapter runs it."},
        "params": {"type": "object", "description": "Action arguments (adapter-interpreted)."},
        "target": _TARGET_SCHEMA,
        "preconditions": {"type": "array", "items": _PRECONDITION_SCHEMA,
                          "description": "Checked against live state BEFORE dispatch (fail-closed)."},
        "verify": {"type": "array", "items": _PRECONDITION_SCHEMA,
                   "description": "Post-conditions checked AFTER dispatch to confirm the intended end-state."},
        "rollback": _ROLLBACK_SCHEMA,
        "note": {"type": "string"},
    },
}

PLAN_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Interlock plan",
    "type": "object",
    "required": ["schema_version", "plan_id", "plan_hash", "status", "body"],
    "additionalProperties": False,
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "plan_id": {"type": "string", "minLength": 1},
        "plan_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "status": {"enum": PLAN_STATES},
        # envelope lifecycle fields the store/gate fill in — NOT hashed (outside body).
        "proposed_at": {"type": "string"},
        "approval": {"type": ["object", "null"]},
        "body": {
            "type": "object",
            "required": ["intent", "stages"],
            "additionalProperties": False,
            "properties": {
                "intent": {"type": "string", "minLength": 1},
                "note": {"type": "string"},
                "stages": {"type": "array", "minItems": 1, "items": _STAGE_SCHEMA},
            },
        },
    },
}


def plan_schema() -> dict:
    """Return the Draft 2020-12 plan schema (a fresh reference each call is unnecessary;
    the dict is treated as read-only)."""
    return PLAN_SCHEMA
