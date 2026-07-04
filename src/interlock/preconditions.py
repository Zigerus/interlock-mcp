# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Precondition engine — typed checks re-evaluated against LIVE ground truth, fail-closed.

Before a mutating stage is dispatched, Interlock re-reads the world and confirms the
stage's preconditions still hold. This is what makes an approval trustworthy across time:
a plan approved an hour ago does not fire if reality has since drifted (the port got
taken, the resource disappeared, memory ran out).

Split of responsibilities (so the core stays generic and unit-testable):
  * The CORE owns the comparison operators (``equals``/``not_equals``/``at_least``/
    ``at_most``/``contains``) — pure, exhaustively tested here.
  * A :class:`ProbeAdapter` owns *observation*: given a check kind + a probe spec, return
    the observed value (or declare it unprobeable). Adapters are where the world lives.

Fail-closed is the rule, not the exception: a required precondition whose check the
adapter cannot probe, or whose operator can't be interpreted, HOLDS=False. A precondition
the executor cannot verify is never silently passed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = ["ProbeResult", "ProbeAdapter", "compare", "evaluate_preconditions", "PreconditionOutcome"]


@dataclass
class ProbeResult:
    """What an adapter observed for one check.
      probeable=False -> the adapter has no probe for this check kind -> fail-closed.
      observed        -> the value to compare (str/bool/int/float), when probeable.
    """
    probeable: bool
    observed: Any = None
    detail: str = ""


@runtime_checkable
class ProbeAdapter(Protocol):
    def probe(self, check: str, probe: dict) -> ProbeResult:
        """Observe live ground truth for ``check`` described by ``probe`` (adapter-defined).
        MUST NOT mutate anything — probing is read-only by contract."""
        ...


def _num(x: Any) -> float | None:
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return None


def compare(observed: Any, op: str, value: str) -> bool | None:
    """Apply a precondition operator. Returns None for an uninterpretable comparison
    (e.g. a numeric operator on a non-numeric observation) -> the caller fails closed.

    ``value`` is always the plan's typed STRING; ``observed`` is whatever the adapter
    returned. equals/not_equals normalize both sides to strings (so bool True and the
    string 'true' compare equal by intent); at_least/at_most are numeric; contains is
    substring on the string form.
    """
    if op in ("at_least", "at_most"):
        ov, wv = _num(observed), _num(value)
        if ov is None or wv is None:
            return None
        return ov >= wv if op == "at_least" else ov <= wv
    if op in ("equals", "not_equals"):
        same = _norm(observed) == _norm(value)
        return same if op == "equals" else not same
    if op == "contains":
        return value in _str(observed)
    return None  # unknown operator -> fail-closed


def _norm(x: Any) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x).strip().lower()


def _str(x: Any) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


@dataclass
class PreconditionOutcome:
    holds: bool
    results: list[dict]  # one per precondition: {check, op, value, observed, status, detail}

    @property
    def failures(self) -> list[dict]:
        return [r for r in self.results if r["status"] != "pass"]


def evaluate_preconditions(preconditions: list[dict], adapter: ProbeAdapter) -> PreconditionOutcome:
    """Evaluate a stage's preconditions against live state via ``adapter``. Fail-closed:
    an unprobeable check or uninterpretable operator yields status != 'pass' and holds=False.
    An empty precondition list HOLDS (nothing to check — e.g. a read-only stage)."""
    results: list[dict] = []
    for pc in (preconditions or []):
        check = pc.get("check")
        expect = pc.get("expect") or {}
        op, value = expect.get("op"), str(expect.get("value"))
        r = adapter.probe(check, pc.get("probe") or {})
        rec = {"check": check, "op": op, "value": value, "observed": None, "status": "fail", "detail": ""}
        if not isinstance(r, ProbeResult):
            rec["detail"] = "probe adapter returned a non-ProbeResult"
        elif not r.probeable:
            rec["detail"] = f"unprobeable: {r.detail or 'adapter has no probe for this check'}"
        else:
            rec["observed"] = r.observed
            verdict = compare(r.observed, op, value)
            if verdict is None:
                rec["detail"] = f"uninterpretable comparison ({op!r} on observed {r.observed!r})"
            else:
                rec["status"] = "pass" if verdict else "fail"
                rec["detail"] = r.detail
        results.append(rec)
    return PreconditionOutcome(holds=all(r["status"] == "pass" for r in results), results=results)
