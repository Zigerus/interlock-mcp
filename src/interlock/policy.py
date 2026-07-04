# Copyright 2026 Zigerus
# SPDX-License-Identifier: Apache-2.0
"""Deployment policy — the domain knowledge the generic core is deliberately without.

A :class:`Policy` tells the validator, per *this* deployment:
  * which actions MUTATE state (so a rollback + preconditions are required),
  * which actions/targets are FORBIDDEN outright,
  * what a plaintext SECRET looks like (so it never lands in a plan),
  * how to treat an action the registry doesn't know.

Keeping this out of the schema is what makes Interlock reusable: the same core governs a
Docker homelab and a Kubernetes fleet; only the policy differs. Ship a policy as code or
load one from a dict (e.g. parsed from YAML/JSON config) via :meth:`Policy.from_dict`.

A Policy is where *all* the domain-specific knowledge the generic core needs lives — not
only action classification and forbidden/secret rules, but also (optionally) the deployment's
**schema extension** (extra plan fields, via :class:`~interlock.schema.SchemaExtension`) and
its **custom invariants** (extra validation rules beyond the built-in seven, via
:class:`CustomInvariant`). Because ``validate()`` receives the Policy on both the propose and
the execute path, bundling these here guarantees a plan is validated under the *same* schema
and invariants at both ends — a plan can never be approvable at propose time yet rejected at
execute time because the two used different rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .schema import SchemaExtension

__all__ = ["ActionSpec", "CustomInvariant", "Policy", "DEFAULT_SECRET_PATTERNS", "DIGEST_RE"]

# Secret-VALUE patterns. A ".env reference", "$VAR", or key *name* does not match these;
# an actual embedded credential does. Deployments may extend/replace this list.
DEFAULT_SECRET_PATTERNS: tuple[str, ...] = (
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",  # JWT
    r"\bsk-[A-Za-z0-9]{16,}",                     # sk- API keys
    r"\bghp_[A-Za-z0-9]{20,}",                    # GitHub PAT
    r"\bAKIA[0-9A-Z]{16}\b",                      # AWS access key id
    r"\b[0-9a-f]{32,}\b",                         # long hex (token / raw hash)
)
# Content-address digests (sha256:/sha512:<hex>) are PUBLIC identifiers, not secrets —
# and image-pin-style actions REQUIRE them. Neutralized before the long-hex scan so a
# legitimate '@sha256:<hex>' ref doesn't false-trip, while a bare long-hex token still does.
DIGEST_RE = re.compile(r"\b(?:sha256|sha512):[0-9a-f]{32,}\b")


@dataclass(frozen=True)
class ActionSpec:
    """Classification of one action verb. ``mutating`` drives the rollback +
    precondition invariants; ``creating`` marks actions that bring a new resource into
    existence (deployments may use it for extra record-keeping rules)."""
    mutating: bool = False
    creating: bool = False


@dataclass(frozen=True)
class CustomInvariant:
    """A deployment-specific validation rule, run in the SAME pass as the built-in seven.

    ``check(plan, policy)`` inspects the full plan document (``plan["body"]["stages"]`` etc.,
    with the Policy available for action classification) and returns either ``(ok, detail)`` or
    a bare ``bool``. It **must not** raise — the validator wraps every custom invariant
    fail-closed (an exception becomes ``ok=False`` with the exception text as detail), so
    ``validate()`` keeps its contract of never raising on a bad plan. Custom invariants are
    numbered I8, I9, … after the built-ins, but tests/consumers should key on ``name`` (an int
    id shifts if the built-in count ever changes)."""
    name: str
    check: Callable[["dict", "Policy"], "tuple[bool, str] | bool"]


@dataclass
class Policy:
    """A deployment's governance policy. All fields optional — an empty Policy treats
    every action as read-only, which is safe-by-omission for validation but means you
    MUST register your mutating actions for the rollback/precondition invariants to bite.
    """
    action_registry: dict[str, ActionSpec] = field(default_factory=dict)
    forbidden_actions: frozenset[str] = frozenset()
    # each rule is a dict of target fields that ALL must match to forbid, e.g.
    #   {"kind": "vm", "id": "105"}  or  {"kind": "gpu"}
    forbidden_targets: tuple[dict, ...] = ()
    secret_patterns: tuple[str, ...] = DEFAULT_SECRET_PATTERNS
    # how to treat an action absent from the registry:
    #   "reject"   -> unknown actions fail validation (strict; recommended for prod)
    #   "mutating" -> unknown actions are assumed mutating (fail-safe: demands rollback)
    #   "read"     -> unknown actions are assumed read-only (permissive; dev only)
    unknown_action: str = "reject"
    require_preconditions_for_mutating: bool = True
    # optional extension seams (see module docstring): extra plan fields + extra invariants.
    schema_extension: SchemaExtension | None = None
    custom_invariants: tuple[CustomInvariant, ...] = ()

    def __post_init__(self):
        if self.unknown_action not in ("reject", "mutating", "read"):
            raise ValueError(f"unknown_action must be reject|mutating|read, got {self.unknown_action!r}")
        self._secret_res = tuple(re.compile(p) for p in self.secret_patterns)

    # --- action classification ------------------------------------------------
    def spec_for(self, action: str) -> ActionSpec | None:
        """The ActionSpec for an action, or None if unknown to the registry."""
        return self.action_registry.get(action)

    def is_known(self, action: str) -> bool:
        return action in self.action_registry

    def is_mutating(self, action: str) -> bool:
        spec = self.action_registry.get(action)
        if spec is not None:
            return spec.mutating
        return self.unknown_action == "mutating"  # "reject" handled by the known-action invariant

    def is_creating(self, action: str) -> bool:
        spec = self.action_registry.get(action)
        return bool(spec and spec.creating)

    def is_forbidden_action(self, action: str) -> bool:
        return action in self.forbidden_actions

    def is_forbidden_target(self, target: dict | None) -> bool:
        if not isinstance(target, dict):
            return False
        for rule in self.forbidden_targets:
            if all(str(target.get(k)) == str(v) for k, v in rule.items()):
                return True
        return False

    # --- secret scanning ------------------------------------------------------
    def find_secret(self, text: str) -> bool:
        """True if ``text`` looks like an embedded credential (digests excluded)."""
        scan = DIGEST_RE.sub("", text)
        return any(rx.search(scan) for rx in self._secret_res)

    # --- construction ---------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict, *, custom_invariants: tuple[CustomInvariant, ...] = ()) -> "Policy":
        """Build a Policy from plain config (e.g. parsed YAML/JSON).

        ``schema_extension`` may be supplied in the dict as
        ``{"stage_properties": {...}, "body_properties": {...}}`` (JSON-Schema fragments).
        ``custom_invariants`` are Python callables and so cannot come from a config dict —
        pass them explicitly via the keyword argument when loading a policy from config."""
        reg = {a: ActionSpec(mutating=bool(s.get("mutating", False)),
                             creating=bool(s.get("creating", False)))
               for a, s in (d.get("action_registry") or {}).items()}
        ext = d.get("schema_extension")
        schema_extension = SchemaExtension(
            stage_properties=dict((ext or {}).get("stage_properties") or {}),
            body_properties=dict((ext or {}).get("body_properties") or {}),
            target_schema=(ext or {}).get("target_schema"),
        ) if ext else None
        return cls(
            action_registry=reg,
            forbidden_actions=frozenset(d.get("forbidden_actions") or ()),
            forbidden_targets=tuple(d.get("forbidden_targets") or ()),
            secret_patterns=tuple(d.get("secret_patterns") or DEFAULT_SECRET_PATTERNS),
            unknown_action=d.get("unknown_action", "reject"),
            require_preconditions_for_mutating=bool(d.get("require_preconditions_for_mutating", True)),
            schema_extension=schema_extension,
            custom_invariants=tuple(custom_invariants),
        )


def registry(mutating: Iterable[str] = (), creating: Iterable[str] = (),
             read_only: Iterable[str] = ()) -> dict[str, ActionSpec]:
    """Convenience builder for an action registry from name lists.
    ``creating`` implies mutating."""
    reg: dict[str, ActionSpec] = {}
    for a in read_only:
        reg[a] = ActionSpec(mutating=False)
    for a in mutating:
        reg[a] = ActionSpec(mutating=True)
    for a in creating:
        reg[a] = ActionSpec(mutating=True, creating=True)
    return reg
