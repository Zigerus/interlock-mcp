# Interlock plan schema

A plan is a JSON/YAML document: an **envelope** plus a **hashed body**. The body is the
approval-bound content; everything outside it is metadata the hash must not cover.

```yaml
schema_version: "1"          # binds ALONGSIDE plan_hash (a bump voids prior approvals)
plan_id: "<opaque id>"       # any non-empty string (the server generates a uuid4)
plan_hash: "<64-hex>"        # sha256( RFC-8785-JCS( body ) )  — computed by the server
status: proposed             # draft|proposed|approved|rejected|executing|executed|halted|expired
approval: null               # filled by the gate on approval; NOT hashed
body:
  intent: "restart the web frontend"   # human-readable; required
  stages:
    - id: s1                            # unique within the plan; required
      action: restart_service          # opaque to the core — a Policy classifies it, an adapter runs it
      target: {kind: service, id: web} # what it acts on (kind+id required; extra fields allowed)
      params: {graceful: "true"}       # adapter-interpreted arguments
      preconditions:                   # checked against LIVE state BEFORE dispatch (fail-closed)
        - check: service_running
          probe: {id: web}             # adapter-interpreted probe spec
          expect: {op: equals, value: "true"}
      verify:                          # post-conditions checked AFTER dispatch
        - check: service_running
          probe: {id: web}
          expect: {op: equals, value: "true"}
      rollback:                        # required for mutating stages (Policy decides "mutating")
        action: restart_service
        target: {kind: service, id: web}
        params: {}
```

## Fields

### Envelope (not hashed)
| field | type | notes |
|---|---|---|
| `schema_version` | `"1"` | Const for this schema. Binds with `plan_hash`. |
| `plan_id` | string | Non-empty. |
| `plan_hash` | 64-hex | `sha256(RFC-8785-JCS(body))`. Recomputed at validate and execute time. |
| `status` | enum | Lifecycle state. |
| `approval` | object\|null | Countersignature record (`approved_by`, `reasoning`, `approved_at`, `binding`). |
| `proposed_at` | string | Set when proposed. |

### Body (hashed)
| field | type | notes |
|---|---|---|
| `intent` | string | Required, non-empty. |
| `note` | string | Optional. |
| `stages` | array | ≥1 stage. |

### Stage
| field | type | notes |
|---|---|---|
| `id` | string | Required, unique in the plan. |
| `action` | string | Required. Opaque; classified by Policy, executed by an adapter. |
| `target` | object | `{kind, id, ...}`. Optional but recommended. |
| `params` | object | Adapter-interpreted. |
| `preconditions` | array | Pre-dispatch checks (see below). |
| `verify` | array | Post-dispatch checks (same shape). |
| `rollback` | object | Compensating stage `{action, params?, target?}` **or** `{irreversible: true, justification}`. |

### Precondition / verify
```yaml
check: <string>              # check kind — the probe adapter must implement it
probe: {<adapter-specific>}  # what to probe
expect:
  op: equals | not_equals | at_least | at_most | contains
  value: "<string>"          # ALWAYS a typed string (hash stability + no YAML 1.1 coercion)
```
`equals`/`not_equals` normalize both sides to lowercase strings (so bool `true` and the
string `"true"` match by intent); `at_least`/`at_most` are numeric; `contains` is substring.
A numeric op on a non-numeric observation is **uninterpretable → fail-closed**.

## Why `value` is always a string

YAML 1.1 coerces `on/off/yes/no` to booleans and reinterprets `1.0`/octal/sexagesimal
numbers. Typing every `value` (and hashing over a YAML-1.2 value model) keeps `plan_hash`
reproducible and prevents a precondition from silently changing meaning across parsers.

## Extending the schema (without forking it)

The base schema is `additionalProperties: false` at the plan, body, and stage levels — an
unknown field is a hard error. A deployment that needs to carry its own fields (a
`risk_class` on the body, an `owner` block or an array-of-objects `approvals` on a stage)
declares them with a **`SchemaExtension`** instead of editing the schema:

```python
from interlock.schema import SchemaExtension
from interlock.policy import Policy

ext = SchemaExtension(
    body_properties={"risk_class": {"enum": ["low", "medium", "high"]}},
    stage_properties={
        "owner": {"type": "string"},
        "approvals": {"type": "array", "items": {
            "type": "object", "required": ["team", "ref"], "additionalProperties": False,
            "properties": {"team": {"type": "string"}, "ref": {"type": "string"}}}},
    },
)
policy = Policy(action_registry=..., schema_extension=ext)   # carried on the Policy
```

Rules that keep the seam a seam, not a bypass:

- The extension **adds** the fields you name to the schema's `properties`; it does **not**
  touch `additionalProperties`. An *undeclared* field still fails validation — you widen the
  schema by exactly the fields you declare and no more.
- Extension fields may only **add**; naming a field that already exists in the base
  (`action`, `params`, …) raises `ValueError` (an extension can't redefine a built-in).
- Extension fields live inside `body`, so they are **hashed** like any other body field — an
  approval binds them, and editing one after approval voids it. The extension is
  validation-only; it does not change how the hash is computed.
- There is no `target_properties` (the target object is already `additionalProperties: true`,
  so extra target fields need no declaration) — but the one thing add-only merging *can't* do
  is change a **required** built-in field. If your targets are keyed `{type, id}` (or any shape
  other than the base `{kind, id}`), set `SchemaExtension(target_schema=...)` to **replace** the
  target subschema wholesale — applied at both the stage target and the compensating-rollback
  target. It's a deliberate override of the schema's most permissive node (target is already
  `additionalProperties: true`); it leaves the body bytes — and therefore `plan_hash` —
  unchanged, and does not affect forbidden-target policy (which matches the target *value*, not
  its *schema*). Example: `SchemaExtension(target_schema={"type": "object", "required": ["type", "id"], "properties": {"type": {"type": "string"}, "id": {"type": "string"}}, "additionalProperties": True})`.

## Custom invariants

Beyond the built-in seven, a deployment can register extra validation rules as
**`CustomInvariant`s** on the Policy — run in the same validation pass, numbered `I8, I9, …`,
and folded into `approvable`:

```python
from interlock.policy import Policy, CustomInvariant

def _mutating_needs_sre(plan, policy):
    bad = [s["id"] for s in plan["body"]["stages"]
           if policy.is_mutating(s.get("action"))
           and not any(a.get("team") == "sre" for a in s.get("approvals", []))]
    return (not bad, f"mutating stages without sre sign-off: {bad}" if bad else "")

policy = Policy(action_registry=..., schema_extension=ext,
                custom_invariants=(CustomInvariant("mutating-needs-sre", _mutating_needs_sre),))
```

A custom `check(plan, policy)` returns `(ok, detail)` (or a bare `bool`) and **must not**
raise — the validator wraps each one fail-closed, so a check that throws on a malformed plan
becomes a *failed* invariant, never an exception out of `validate()`. Both seams ride on the
Policy, so a plan is validated under identical rules at propose time and execute time.

## Hashing (normative)

`plan_hash = lowercasehex(sha256(RFC-8785-JCS(YAML-1.2-value-model(body))))`. Hash the
**body value model only** — never the source text, never with a YAML-1.1 loader. Extension
fields live in the body and are hashed like built-in fields. See `src/interlock/hashing.py`
and its pinned cross-implementation vector.
