# interlock-mcp

**A human-in-the-loop governance interlock for AI agents (MCP server).** Agents *propose*
changes; a human *countersigns the exact plan*; only then does it *execute* — stage by
stage, precondition-checked against live state, verified, and audited. Bring your own
executors.

> An *interlock* is a safety mechanism that prevents an action until every required
> condition is engaged. Nothing here actuates unless the plan validates, a human
> countersigns those exact bytes, and the live preconditions still hold.

---

## Why this exists

Most ways of letting an agent change real systems fall into two camps, and neither is safe
enough for infrastructure:

- **Direct-execute tool servers** (docker/shell/k8s MCPs) hand the model the keys — it
  plans *and* applies in one step. No review, no verification, no audit.
- **Synchronous human-in-the-loop** (elicitation, approval dialogs) pauses a single tool
  call to ask *right now, in-session*. That doesn't fit changes a human should review
  *out-of-band*, minutes or hours later, from a different surface.

Interlock is the missing envelope: an **asynchronous, hash-bound, human-countersigned,
precondition-checked, verified, audited** path from agent intent to real change. The
agent never holds the keys; it holds a *proposal*.

## The loop

```mermaid
   agent                    interlock core                      human            world
     │  propose(body)             │                               │                │
     ├───────────────────────────▶│ validate (schema+invariants)  │                │
     │                            │ hash (RFC-8785 JCS)           │                │
     │        plan_id  ◀──────────┤ store as PROPOSED (held)      │                │
     │                            │                               │                │
     │                            │        review + countersign   │                │
     │                            │◀──────────────────────────────┤ interlock approve
     │                            │ bind (schema_version, hash)   │                │
     │  execute(plan_id)          │                               │                │
     ├───────────────────────────▶│ re-validate + release gate    │                │
     │                            │  per stage:                   │                │
     │                            │   ├ preconditions vs LIVE state│───probe──────▶│
     │                            │   ├ dispatch (adapter) ────────┼───execute────▶│
     │                            │   └ verify post-conditions ────│───probe──────▶│
     │        result  ◀───────────┤ halt-and-audit on any failure │                │
     │                            │ append to hash-chained audit  │                │
```

## Guarantees

- **Hash-bound approval.** An approval binds `(schema_version, plan_hash)` to the exact
  bytes reviewed. Edit the body afterward and the approval is void (tamper-evident).
- **One-shot & time-boxed.** An approved plan runs once; a stale approval expires.
- **Fail-closed preconditions.** A stage's preconditions are re-checked against *live*
  ground truth immediately before dispatch. Unmet — or unprobeable — halts with nothing
  dispatched.
- **Forward-only.** On any failure it halts and records what committed; no surprise
  auto-rollback. Remediation is a new plan.
- **Tamper-evident audit.** Every decision is appended to a hash-chained log;
  `interlock verify-audit` detects any edit, reorder, or drop.
- **Reproducible hashing.** RFC-8785 JCS over a YAML-1.2 value model — no `on/off→bool`
  coercion, no source-text hashing. Any re-implementation must reproduce the pinned vector.

## Quickstart

```bash
pip install interlock-mcp            # or: pip install "interlock-mcp[server]" for the MCP server

# run the dependency-free demo (propose -> approve -> execute -> verify a file write)
python examples/filesystem_demo.py
```

Embed it in a few lines — implement two adapters for your world and the core does the rest:

```python
from interlock.engine import Interlock
from interlock.policy import Policy, registry
from interlock.approval import FileStore
from interlock.audit import FileAuditSink

engine = Interlock(
    policy=Policy(action_registry=registry(mutating=["restart_service"])),
    store=FileStore("./plans"), audit=FileAuditSink("./audit.jsonl"),
    executor=MyExecutor(),   # .execute(action, params, target) -> ExecResult
    prober=MyProber(),       # .probe(check, probe) -> ProbeResult  (read-only)
    ttl_seconds=72 * 3600,
)
```

The agent talks to the **MCP server** (`propose_plan`, `get_plan`, `list_plans`,
`execute_plan`). A human reviews on a **separate channel**:

```bash
interlock list --status proposed
interlock approve <plan_id> --by alice --reason "reviewed"
interlock verify-audit ./audit.jsonl
```

## Security model (in one sentence)

The **proposer and the approver are different surfaces**: the agent's MCP tools can
propose and execute, but *cannot approve* — approval is a human action on the CLI/admin
channel, so nothing the model can call flips a plan to approved. Details in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Concepts

| Piece | What it is |
|---|---|
| **Plan** | An envelope + a hashed `body` of ordered **stages** (`action`, `target`, typed `preconditions`, `verify`, `rollback`). Actions are opaque to the core. |
| **Policy** | Your deployment's domain knowledge: which actions mutate, which actions/targets are forbidden, what a secret looks like. Not baked into the schema. |
| **Invariants** | Seven universal checks the validator enforces (schema, hash-recompute, unique ids + known actions, mutating→rollback, mutating→preconditions, no-forbidden, no-secrets). |
| **Adapters** | Two small protocols — `ExecutorAdapter.execute(...)` and `ProbeAdapter.probe(...)` — the only place your infrastructure appears. |

See [`docs/SCHEMA.md`](docs/SCHEMA.md), [`docs/PROTOCOL.md`](docs/PROTOCOL.md), and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Status

**Alpha (0.1).** The deterministic core (hashing, schema, validator, precondition engine)
and the approval/audit/executor layer are covered by an adversarial test suite. APIs may
shift before 1.0. Issues and review welcome.

## License

Apache-2.0 © Zigerus. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
