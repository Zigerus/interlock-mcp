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

import copy
from dataclasses import dataclass, field

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
    the dict is treated as read-only — never mutate it in place; see SchemaExtension.apply)."""
    return PLAN_SCHEMA


@dataclass(frozen=True)
class SchemaExtension:
    """Consumer-declared extra plan fields, merged into the generic schema at validation
    time — so a deployment can carry domain-specific fields **without forking the schema**.

    Each mapping is ``{field_name: <JSON-Schema fragment>}`` merged into the ``properties``
    of the named node. ``additionalProperties: False`` stays in force everywhere, so the
    extension widens the schema by *exactly* the fields you name and no more — an
    **undeclared** field still rejects. That is the whole point: the seam adds fields, it
    does not open the schema.

      * ``stage_properties`` — merged into every stage object's properties
        (e.g. a domain ``priority``, an ``owner`` block, an array-of-objects ``approvals``).
      * ``body_properties``  — merged into the plan body's properties
        (e.g. a ``change_window`` object, a ``risk_class`` enum).

    For extra *fields on a stage's or the body's* objects, there is deliberately no
    ``target_properties``: the target object is already ``additionalProperties: True``, so
    extra target fields (host, region, …) are always allowed without declaration.

    The one thing add-only field merging cannot do is change a **required** built-in field —
    e.g. a deployment whose targets are keyed ``{type, id}`` rather than the base's
    ``{kind, id}``. For that, and only that, ``target_schema`` **replaces** the target
    subschema wholesale (at every place a target appears — a stage's ``target`` and a
    compensating rollback's ``target``). This is a deliberate, explicit override of the most
    permissive node in the schema (target is already ``additionalProperties: True``); it does
    not touch the hash — the body bytes are unchanged, so ``plan_hash`` is unchanged — and it
    does not affect forbidden-target policy (that matches on the target *value*, independent of
    the target *schema*). Use it to fit an existing plan vocabulary without a fork; leave it
    ``None`` to keep the base ``{kind, id}`` contract.

    Extension fields live inside ``body``, so they participate in ``plan_hash`` exactly like
    built-in fields — an approval binds them too. Extensions are validation-only; they do
    not change how the hash is computed.
    """
    stage_properties: dict = field(default_factory=dict)
    body_properties: dict = field(default_factory=dict)
    target_schema: dict | None = None  # full replacement for the target subschema (both uses)

    def apply(self, base_schema: dict) -> dict:
        """Return a NEW schema (deep-copied) with the declared fields merged in and, if set,
        the target subschema replaced.

        The base is **never** mutated — critical, because ``plan_schema()`` returns a shared
        module-level dict; an in-place merge would silently extend the schema for every later
        ``validate()`` call in the process. Raises ``ValueError`` if an extension names a field
        that already exists in the base (extensions may only ADD fields, never redefine a
        built-in — that could weaken a guarantee)."""
        schema = copy.deepcopy(base_schema)
        body_props = schema["properties"]["body"]["properties"]
        stage_props = body_props["stages"]["items"]["properties"]
        self._merge(body_props, self.body_properties, "body")
        self._merge(stage_props, self.stage_properties, "stage")
        if self.target_schema is not None:
            # replace the target subschema at BOTH sites it appears: a stage's target and a
            # compensating-rollback stage's target (the irreversible-marker rollback has none).
            stage_props["target"] = copy.deepcopy(self.target_schema)
            for branch in stage_props.get("rollback", {}).get("oneOf", []):
                if isinstance(branch, dict) and "target" in branch.get("properties", {}):
                    branch["properties"]["target"] = copy.deepcopy(self.target_schema)
        return schema

    @staticmethod
    def _merge(target_props: dict, additions: dict, level: str) -> None:
        for name, fragment in additions.items():
            if name in target_props:
                raise ValueError(
                    f"SchemaExtension: {level} field {name!r} already exists in the base schema — "
                    "extensions may only ADD fields, not redefine built-ins "
                    "(use target_schema to replace the target subschema)")
            target_props[name] = copy.deepcopy(fragment)
