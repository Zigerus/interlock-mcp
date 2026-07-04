# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the canonical hasher — the trust anchor.

Run: python -m pytest tests/test_hashing.py   (or: python tests/test_hashing.py)
"""
import io
import sys
from pathlib import Path

import pytest
from ruamel.yaml import YAML

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from interlock.hashing import canonical_hash, plan_hash_from_body, plan_hash_from_document  # noqa: E402


def load_yaml_12(text: str):
    """The NORMATIVE loader discipline: YAML 1.2, no 1.1 type coercion."""
    y = YAML(typ="safe")
    y.version = (1, 2)
    return y.load(io.StringIO(text))


# --- determinism + reproducibility -------------------------------------------
def test_deterministic():
    body = {"stages": [{"id": "s1", "action": "noop", "params": {"n": "1"}}]}
    assert plan_hash_from_body(body) == plan_hash_from_body(body)


def test_key_order_independent():
    a = {"b": "2", "a": "1", "c": {"y": "1", "x": "2"}}
    b = {"a": "1", "c": {"x": "2", "y": "1"}, "b": "2"}
    assert canonical_hash(a) == canonical_hash(b)


def test_whitespace_and_comment_independent():
    t1 = "stages:\n- id: s1\n  action: noop\n"
    t2 = "# a comment\nstages:\n  - id: s1     # trailing\n    action: noop\n\n"
    assert canonical_hash(load_yaml_12(t1)) == canonical_hash(load_yaml_12(t2))


def test_known_vector_is_pinned():
    # A pinned cross-implementation vector: if this hash ever changes, the canonical
    # form changed and every prior approval's meaning changed with it. Any port (TS,
    # Go, ...) MUST reproduce this exact digest for this exact value model.
    body = {"intent": "demo", "stages": [{"id": "s1", "action": "noop", "params": {}}]}
    assert canonical_hash(body) == "eca51633e44978d9059a2aa05525481b8bf18650a83dca0868532cff7eb5e4fe"


# --- the YAML 1.1 -> bool footgun (why the loader discipline is normative) ----
def test_on_off_stays_string_under_yaml_12():
    v = load_yaml_12("state: on\nflag: off\nname: yes\n")
    assert v == {"state": "on", "flag": "off", "name": "yes"}, v  # NOT booleans


def test_string_true_differs_from_bool_true():
    # "value: 'true'" (string) and "value: true" (bool) are DIFFERENT value models and
    # MUST hash differently — this is why safety-check values are typed strings.
    assert canonical_hash({"value": "true"}) != canonical_hash({"value": True})


def test_numeric_string_differs_from_number():
    assert canonical_hash({"port": "8211"}) != canonical_hash({"port": 8211})


# --- tamper-evidence ----------------------------------------------------------
def test_one_byte_change_changes_hash():
    base = {"stages": [{"id": "s1", "action": "compose_up", "params": {"dir": "palworld"}}]}
    tampered = {"stages": [{"id": "s1", "action": "compose_up", "params": {"dir": "palwor1d"}}]}
    assert canonical_hash(base) != canonical_hash(tampered)


def test_nested_reorder_stable_but_list_order_significant():
    # dict key order irrelevant; LIST order IS significant (stage order matters).
    assert canonical_hash({"s": [1, 2]}) != canonical_hash({"s": [2, 1]})


# --- document helper + loud failures -----------------------------------------
def test_document_hashes_body_only():
    doc = {"schema_version": "1", "plan_id": "x", "plan_hash": "IGNORED", "status": "draft",
           "body": {"stages": []}}
    assert plan_hash_from_document(doc) == canonical_hash({"stages": []})


def test_document_without_body_raises():
    with pytest.raises(KeyError):
        plan_hash_from_document({"schema_version": "1"})


def test_non_json_value_fails_loud():
    import datetime
    with pytest.raises((TypeError, ValueError)):
        canonical_hash({"when": datetime.datetime(2026, 7, 4)})


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
