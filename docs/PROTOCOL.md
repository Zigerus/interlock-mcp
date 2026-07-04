# Interlock protocol

The lifecycle a plan moves through, and the surfaces that drive it.

## States

```
draft ──propose──▶ proposed ──approve──▶ approved ──execute──▶ executing ──▶ executed
                      │                      │                                  │
                      └──────reject──────────┴──▶ rejected            (halt)──▶ halted
```

A plan is only ever `proposed` if it validated approvable. `approved` binds the exact
`(schema_version, plan_hash)`. `executed`/`halted`/`rejected` are terminal.

## Agent surface (MCP server)

The proposing agent gets exactly these tools — and **not** approve/reject.

| tool | effect |
|---|---|
| `propose_plan(body)` | Validate the body under policy. If approvable, store it `proposed` and return `plan_id`; else return the failing invariants (nothing stored). The server computes the hash. |
| `get_plan(plan_id)` | The full plan document + status + approval. |
| `list_plans(status?)` | Plans, optionally filtered by status. |
| `execute_plan(plan_id)` | Run an **approved** plan through the gated executor. On a non-approved / expired / tampered plan it returns `rejected` — the *gate* enforces approval, never the caller. |

## Human surface (CLI / your admin UI)

Approval is a separate channel. Reference CLI (`interlock`):

| command | effect |
|---|---|
| `list [--status S]` | List plans. |
| `show <plan_id>` | Full plan JSON. |
| `approve <plan_id> --by NAME [--reason ...]` | Prints the exact body + `plan_hash`, then countersigns. Binds `(schema_version, plan_hash)`. |
| `reject <plan_id> --by NAME [--reason ...]` | Reject. |
| `verify-audit <audit.jsonl>` | Verify the audit hash chain. |

Point both surfaces at the same engine (`INTERLOCK_CONFIG=<module with build()>`) so they
share one plan store + audit log.

## Execute-time gates (in order)

1. **Re-validate** the plan under the current policy. A plan that isn't approvable *now*
   never runs (policy may have tightened; body may be malformed).
2. **Release gate** (`check_release`): status is `approved`; within TTL; `schema_version`
   matches the binding; the body still hashes to the approved `plan_hash`.
3. **Per stage**: preconditions vs. live state (fail-closed) → dispatch (adapter) →
   verify post-conditions. Any failure → **halt** (forward-only) + audit.

## Adapters

Two protocols, both small; the only place your infrastructure appears:

```python
class ExecutorAdapter(Protocol):
    def execute(self, action: str, params: dict, target: dict | None) -> ExecResult: ...

class ProbeAdapter(Protocol):
    def probe(self, check: str, probe: dict) -> ProbeResult: ...   # MUST be read-only
```

`ExecResult(ok, detail)`; `ProbeResult(probeable, observed, detail)`. An unprobeable
required precondition is fail-closed. Reference implementations that adapt plain callables
live in `interlock.adapters.command`.

## Extension seams (domain fields + custom invariants)

The core schema and its seven invariants are domain-agnostic. A deployment that needs more
declares it on the **Policy** — never by forking the core — through two seams that ride
alongside the adapters:

- **`schema.SchemaExtension`** — extra plan fields (`Policy(schema_extension=...)`). Merged
  into the schema for validation; `additionalProperties: false` stays in force so an
  *undeclared* field still rejects. Extension fields live in `body` and are hashed.
- **`policy.CustomInvariant`** — extra validation rules (`Policy(custom_invariants=(...,))`),
  run in the same pass as the built-in seven, numbered `I8+`, each wrapped fail-closed.

Both seams are carried on the Policy, which `validate()` receives on **both** the propose and
the execute path — so a plan is validated under identical schema + invariants at both ends
(no "approvable at propose, rejected at execute" divergence). See [`SCHEMA.md`](SCHEMA.md#extending-the-schema-without-forking-it).

## Async by design

`propose` returns immediately with a durable `plan_id`; approval happens whenever the
human gets to it; `execute` is a later call. Interlock does not require the agent's session
to stay open between propose and execute — mirroring the MCP "call-now, fetch-later" task
pattern, but with the review and verification the task primitive doesn't provide.
