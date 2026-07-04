# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Adapters — the seam between the generic core and your world.

The core speaks two protocols and knows nothing else about your infrastructure:
  * :class:`~interlock.executor.ExecutorAdapter` — performs ONE action (the only
    side-effecting call in the system).
  * :class:`~interlock.preconditions.ProbeAdapter` — observes live ground truth for a
    check (read-only by contract).

This package ships safe, generic reference adapters (:mod:`interlock.adapters.command`)
that adapt deployer-provided argv-builders and probe callables into those protocols —
so "bring your own executor" is a few small functions, not a fork.
"""
from interlock.executor import ExecResult, ExecutorAdapter  # noqa: F401
from interlock.preconditions import ProbeAdapter, ProbeResult  # noqa: F401

__all__ = ["ExecResult", "ExecutorAdapter", "ProbeAdapter", "ProbeResult"]
