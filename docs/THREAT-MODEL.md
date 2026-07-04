# Interlock threat model

What Interlock defends against, what it explicitly does not, and the trust boundaries you
must uphold when you deploy it. Interlock is a governance *envelope* — it is only as strong
as the boundaries around it.

## Assets

- **The right to change your systems.** The core asset: only a human-countersigned,
  precondition-satisfied plan should ever mutate anything.
- **The audit record.** A truthful, tamper-evident account of what was decided and done.

## Trust boundaries

```
  untrusted            semi-trusted                 trusted (human)         world
  ────────             ────────────                 ───────────────        ─────
  proposing  ── MCP ──▶ interlock core  ◀── CLI ──   operator           ── adapters ──▶ infra
  agent (LLM)           (validate/gate/                (approves)
                         execute/audit)
```

- The **proposing agent is untrusted**. It may propose anything; it cannot approve, and it
  cannot make an unapproved or tampered plan execute.
- The **core is deterministic and does not call the model.** Validation, hashing,
  preconditions, and the gate are pure code.
- The **operator is the trust root** for authorizing change. Interlock makes their
  decision precise (they countersign exact bytes) and attributable (named approver).

## Threats addressed

| Threat | Mitigation |
|---|---|
| Agent executes a change with no review | Propose ≠ execute; nothing runs before a human approval. |
| Agent self-approves | Approve/reject are **not** on the agent MCP surface (separate human channel). |
| Approved bytes ≠ reviewed bytes ("bait and switch") | Approval binds `(schema_version, plan_hash)`; execute re-hashes the body and refuses on mismatch. |
| Stale approval fires against drifted reality | TTL expiry + per-stage precondition re-check against **live** state at execute time. |
| A precondition can't be verified | Fail-closed: unprobeable/uninterpretable → halt, never a silent pass. |
| Secrets smuggled into a plan | Validator secret-scan (invariant 7); keep credentials in your adapters, not in plans. |
| Forbidden action/target slips through | Policy `forbidden_actions` / `forbidden_targets` (invariant 6). |
| Audit log quietly edited | Hash-chained entries; `verify-audit` detects edits, reorders, and drops. |
| Non-reproducible hash (parser divergence) | RFC-8785 JCS over a YAML-1.2 value model; pinned cross-impl vector; typed-string values. |
| Double execution / replay | One-shot: execute persists a terminal status; the release gate then refuses. |

## Threats NOT addressed (your responsibility)

- **Adapter safety.** Interlock validates and gates *which* action runs; your
  `ExecutorAdapter` decides *how*. A reckless adapter (shell-string interpolation, an
  over-broad command) is a hole Interlock cannot close. Build total, least-privilege,
  argv-based adapters. The reference `CommandExecutor` uses `shell=False` by design.
- **Authentication / transport.** Interlock does not authenticate MCP callers or the CLI
  operator, and does not encrypt anything. Put it behind your own auth: restrict the MCP
  server to the intended agent, and the approval channel to real operators (an MCP gateway,
  SSH, an authenticated admin UI). The proposer/approver separation is only meaningful if
  the approval channel is actually restricted to humans.
- **Probe honesty.** Ground-truth guarantees are only as good as your `ProbeAdapter`. A
  probe that lies (or reads the wrong thing) defeats precondition/verify. Probes must be
  read-only and observe the real resource.
- **Policy correctness.** If your action registry marks a mutating action read-only, the
  rollback/precondition invariants won't fire for it. Classify actions honestly; prefer
  `unknown_action="reject"` in production.
- **Secret detection is best-effort.** The scanner catches common credential shapes, not
  all. Don't rely on it as your only control — don't put secrets in plans.
- **Availability / DoS, multi-node concurrency.** The reference `FileStore` is single-node;
  concurrent executes across processes need a store that enforces atomic status transitions.

## Deployment checklist

- [ ] MCP server reachable only by the intended agent(s).
- [ ] Approval channel reachable only by human operators (never the agent).
- [ ] `unknown_action="reject"`; every mutating action registered; forbidden rules set.
- [ ] Adapters argv-based / least-privilege; probes strictly read-only.
- [ ] Durable, access-controlled plan store + audit sink; periodic `verify-audit`.
- [ ] A sensible `ttl_seconds` so stale approvals expire.
