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

## Hashing (normative)

`plan_hash = lowercasehex(sha256(RFC-8785-JCS(YAML-1.2-value-model(body))))`. Hash the
**body value model only** — never the source text, never with a YAML-1.1 loader. See
`src/interlock/hashing.py` and its pinned cross-implementation vector.
