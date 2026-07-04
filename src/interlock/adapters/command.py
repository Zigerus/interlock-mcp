# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Reference adapters — turn deployer-provided callables into the core's protocols.

``CommandExecutor`` runs an action by building an **argv list** (never a shell string,
so there is no shell-injection surface) from a deployer-supplied builder, and reports
success from the exit code. ``CallableProber`` observes a check by calling a
deployer-supplied function; any exception (or an unknown check) is a fail-closed
``probeable=False``, never a silent pass.

These are intentionally thin: the security model does not live in the adapter (that's the
plan validator, the approval gate, and your policy) — the adapter only maps a validated,
approved action onto a concrete command. Keep your argv-builders total and side-effect-only.
"""
from __future__ import annotations

import subprocess
from typing import Any, Callable

from interlock.executor import ExecResult
from interlock.preconditions import ProbeResult

ArgvBuilder = Callable[[dict, dict | None], list[str]]
ProbeFn = Callable[[dict], Any]

__all__ = ["CommandExecutor", "CallableProber"]


class CommandExecutor:
    """ExecutorAdapter: ``action -> argv`` via ``builders[action](params, target)``.

    An action with no registered builder fails closed (``ok=False``) — the executor
    then halts the plan, exactly as for any other stage failure. ``run`` is injectable
    for testing; the default runs argv with ``shell=False`` and a timeout.
    """
    def __init__(self, builders: dict[str, ArgvBuilder], *, timeout: int = 120,
                 run: Callable[[list[str]], tuple[int, str, str]] | None = None) -> None:
        self.builders = builders
        self.timeout = timeout
        self._run = run or self._default_run

    def _default_run(self, argv: list[str]) -> tuple[int, str, str]:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)  # noqa: S603
        return p.returncode, p.stdout, p.stderr

    def execute(self, action: str, params: dict, target: dict | None) -> ExecResult:
        builder = self.builders.get(action)
        if builder is None:
            return ExecResult(ok=False, detail=f"no argv builder registered for action {action!r}")
        try:
            argv = builder(params or {}, target)
        except Exception as e:  # noqa: BLE001
            return ExecResult(ok=False, detail=f"argv builder raised: {type(e).__name__}: {e}")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            return ExecResult(ok=False, detail="argv builder did not return a list[str]")
        try:
            rc, out, err = self._run(argv)
        except Exception as e:  # noqa: BLE001
            return ExecResult(ok=False, detail=f"command error: {type(e).__name__}: {e}")
        excerpt = (out or err or "").strip()[-500:]
        return ExecResult(ok=(rc == 0), detail=f"rc={rc} {excerpt}".strip())


class CallableProber:
    """ProbeAdapter: ``check -> observed`` via ``probes[check](probe_spec)``.

    Unknown check or a raising probe -> ``probeable=False`` (fail-closed). Probe
    functions MUST be read-only.
    """
    def __init__(self, probes: dict[str, ProbeFn]) -> None:
        self.probes = probes

    def probe(self, check: str, probe: dict) -> ProbeResult:
        fn = self.probes.get(check)
        if fn is None:
            return ProbeResult(probeable=False, detail=f"no probe registered for check {check!r}")
        try:
            observed = fn(probe or {})
        except Exception as e:  # noqa: BLE001
            return ProbeResult(probeable=False, detail=f"probe raised: {type(e).__name__}: {e}")
        return ProbeResult(probeable=True, observed=observed)
