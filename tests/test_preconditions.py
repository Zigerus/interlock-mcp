# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Precondition engine tests — operators + fail-closed evaluation."""
from conftest import FakeProbe

from interlock.preconditions import compare, evaluate_preconditions


# --- operators ----------------------------------------------------------------
def test_equals_normalizes_bool_and_string():
    assert compare(True, "equals", "true") is True
    assert compare("Up", "equals", "up") is True          # case-normalized
    assert compare(False, "equals", "true") is False


def test_not_equals():
    assert compare("running", "not_equals", "stopped") is True
    assert compare("running", "not_equals", "running") is False


def test_at_least_at_most_numeric():
    assert compare(10670, "at_least", "10240") is True
    assert compare(9000, "at_least", "10240") is False
    assert compare(50, "at_most", "100") is True


def test_numeric_op_on_nonnumeric_is_none():
    assert compare("lots", "at_least", "10") is None       # fail-closed upstream


def test_contains():
    assert compare("Up 3 minutes (healthy)", "contains", "healthy") is True
    assert compare("Exited", "contains", "healthy") is False


def test_unknown_op_is_none():
    assert compare("x", "wat", "y") is None


# --- evaluation: pass / fail / fail-closed ------------------------------------
def test_empty_preconditions_hold():
    out = evaluate_preconditions([], FakeProbe())
    assert out.holds is True


def test_all_pass():
    pcs = [{"check": "running", "expect": {"op": "equals", "value": "true"}}]
    out = evaluate_preconditions(pcs, FakeProbe({"running": True}))
    assert out.holds is True
    assert out.results[0]["status"] == "pass"


def test_fail_when_observation_mismatches():
    pcs = [{"check": "port_free", "expect": {"op": "equals", "value": "true"}}]
    out = evaluate_preconditions(pcs, FakeProbe({"port_free": False}))
    assert out.holds is False
    assert out.failures[0]["check"] == "port_free"


def test_unprobeable_fails_closed():
    pcs = [{"check": "mystery", "expect": {"op": "equals", "value": "true"}}]
    out = evaluate_preconditions(pcs, FakeProbe(unprobeable={"mystery"}))
    assert out.holds is False
    assert "unprobeable" in out.results[0]["detail"]


def test_uninterpretable_comparison_fails_closed():
    pcs = [{"check": "mem", "expect": {"op": "at_least", "value": "10"}}]
    out = evaluate_preconditions(pcs, FakeProbe({"mem": "not-a-number"}))
    assert out.holds is False
    assert "uninterpretable" in out.results[0]["detail"]


def test_mixed_one_fail_halts_hold():
    pcs = [
        {"check": "a", "expect": {"op": "equals", "value": "true"}},
        {"check": "b", "expect": {"op": "at_least", "value": "5"}},
    ]
    out = evaluate_preconditions(pcs, FakeProbe({"a": True, "b": 3}))
    assert out.holds is False
    assert [r["status"] for r in out.results] == ["pass", "fail"]
