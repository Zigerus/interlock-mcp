# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Canonical plan hashing — the trust anchor of Interlock.

An approval in Interlock binds the PAIR ``(schema_version, plan_hash)``. For that
binding to mean anything, the hash must be:

  * **Reproducible** — the same plan body hashes identically on any machine, in any
    language, regardless of key order, whitespace, or comments.
  * **Value-exact** — it is computed over the canonical *value model* of the plan
    body, never over the source text, so re-serialization can't change it.
  * **Tamper-evident** — any change to the approved body (even a byte) changes the
    hash, which voids the approval.

The recipe (NORMATIVE — documented so re-implementations can match it byte-for-byte):

  1. Take the plan's ``body`` subtree ONLY. Everything outside ``body`` (the
     ``plan_hash`` itself, ``plan_id``, ``status``, ``schema_version``) is excluded —
     ``schema_version`` binds *alongside* the hash, not inside it.
  2. Parse it with a **YAML 1.2** core-schema loader with **no implicit type
     resolution** (ruamel in 1.2/pure mode) — NOT PyYAML ``safe_load``. YAML 1.1
     coerces ``on/off/yes/no`` to booleans and reinterprets ``1.0``/octal/sexagesimal
     numbers, which silently changes the hashed value model. (Verified footgun:
     ``yaml.safe_load("state: on")`` -> ``{"state": True}``.)
  3. Serialize the resulting JSON value model with **RFC 8785 JCS** (sorted keys,
     normalized numbers, minimal string escaping).
  4. ``sha256`` the UTF-8 bytes; lowercase hex.

Do NOT hand-roll number/string canonicalization, and do NOT hash the YAML/JSON source
string — both re-introduce the exact divergences JCS exists to remove.
"""
from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

__all__ = ["canonical_hash", "plan_hash_from_body", "plan_hash_from_document"]


def canonical_hash(value: Any) -> str:
    """Lowercase-hex ``sha256`` of the RFC-8785 JCS serialization of a JSON value.

    ``value`` must already be a JSON value model (dict/list/str/int/float/bool/None)
    — the caller is responsible for having parsed it with a YAML-1.2/JSON loader that
    did NOT coerce types. Raises ``TypeError`` (from rfc8785) on non-JSON values, so a
    stray ``datetime``/``set`` fails loudly rather than hashing to something unstable.
    """
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def plan_hash_from_body(body: Any) -> str:
    """Canonical hash of a plan ``body`` value model (the approval-bound content)."""
    return canonical_hash(body)


def plan_hash_from_document(document: dict) -> str:
    """Canonical hash of the ``body`` field of a full plan document (envelope + body).

    Raises ``KeyError`` if there is no ``body`` — a plan with no body has nothing to
    bind an approval to, and silently hashing ``None`` would be a trap.
    """
    if "body" not in document:
        raise KeyError("plan document has no 'body' to hash")
    return canonical_hash(document["body"])
