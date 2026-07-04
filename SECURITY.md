# Security policy

Interlock is a security-relevant project (it governs whether an agent may change real
systems). Please report vulnerabilities responsibly.

## Reporting

- Use **GitHub Security Advisories** ("Report a vulnerability") on this repository, or
- open a minimal issue asking for a private contact channel (do **not** post exploit
  details in a public issue).

Please include: affected version/commit, a description, and a minimal reproduction. We aim
to acknowledge within a few days.

## Scope

In scope: the deterministic core (hashing, schema, validator, precondition engine), the
approval gate, the audit chain, and the reference adapters/CLI/server.

Out of scope (by design — see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)): the safety
of adapters you write, authentication/transport around the MCP server and approval channel,
and probe honesty. Interlock provides the governance envelope; you provide the boundary.

## Hardening highlights

- Deterministic core; the model is never in the validation/gate/hash path.
- Fail-closed preconditions; hash-bound, one-shot, time-boxed approvals.
- Tamper-evident, hash-chained audit log (`interlock verify-audit`).
- Reference executor uses `shell=False` (argv), so there is no shell-injection surface in
  the shipped adapter.
