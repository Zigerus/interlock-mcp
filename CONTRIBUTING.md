# Contributing

Thanks for your interest. Interlock is a security-relevant project; correctness and clarity
matter more than features.

## Dev setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
python examples/filesystem_demo.py
```

## Ground rules

- **The deterministic core stays deterministic.** No network, filesystem, subprocess, or
  model calls in `hashing`, `schema`, `policy`, `validate`, or `preconditions`. Side
  effects live only in adapters.
- **Fail closed.** New checks default to refusal on anything unverifiable.
- **Don't touch the hash lightly.** Any change that could alter `plan_hash` for an existing
  body is a breaking change to every prior approval — call it out, bump `schema_version`,
  and update the pinned vector in `tests/test_hashing.py` deliberately.
- **Tests with the change.** New behavior comes with adversarial tests. Keep `pytest` green
  and the example passing.
- **Apache-2.0 header** on new source files (`SPDX-License-Identifier: Apache-2.0`).

## Scope

Prefer changes that keep the core generic and push domain specifics into policy/adapters.
Security reports: see [`SECURITY.md`](SECURITY.md).
