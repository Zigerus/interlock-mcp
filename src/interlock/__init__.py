# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Interlock — a human-in-the-loop governance interlock for agent-initiated changes.

Agents *propose*; a human *countersigns the exact plan*; only then does it *execute* —
stage by stage, each stage's preconditions re-checked against live ground truth before
dispatch, then verified and audited. Executors, probes, and the approval backend are
pluggable adapters; the core knows nothing about Docker, SSH, or your hosts.

Public API (stable within a minor version):
    hashing     — canonical, reproducible plan hashing (the trust anchor)
    schema      — the generic plan schema + loader
    policy      — deployment policy (action registry, forbidden rules, secret patterns)
    validate    — deterministic validator (schema + invariants + hash recompute)
    preconditions — typed precondition engine (fail-closed) + probe adapter protocol
"""
__version__ = "0.1.0"
