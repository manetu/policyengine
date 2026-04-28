# Manetu PolicyEngine (MPE) — Essentials Reference

This document is a curated baseline for LLM tooling. It is safe to prepend
verbatim to a system prompt. It covers the concepts, structures, and CLI
commands most commonly needed when working with MPE.

---

## What is PolicyEngine?

Manetu PolicyEngine (MPE) is a high-performance, programmable access-control
and governance layer that protects APIs and sensitive data using
**Policy-Based Access Control (PBAC)**. It is built on
[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and evaluates
policies written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
policy language.

MPE acts as a **Policy Decision Point (PDP)**. Your application (the
**Policy Enforcement Point, PEP**) asks MPE "should I allow this request?" and
MPE returns an allow/deny decision. This cleanly separates authorization logic
from application code.

```
Application (PEP) → PolicyEngine (PDP) → OPA / Rego evaluation
```

MPE is available as:
- An **embeddable Go library** for tight integration.
- A **standalone gRPC / HTTP service** for side-car or centralized deployment.
- A **CLI tool** (`mpe`) for authoring, linting, testing, and serving policies
  locally.

---

## The PORC Model

Every authorization decision in MPE is expressed as a **PORC tuple**:

| Field | Description |
|-------|-------------|
| **P**rincipal | The identity making the request (JWT claims, service account, etc.) |
| **O**peration | The action being attempted (e.g., `petstore:http:get`) |
| **R**esource | The target of the operation, including its resource-group membership |
| **C**onditions | Ambient context — request metadata, environment, scopes granted |

A **Mapper** (Rego module) is responsible for extracting a PORC tuple from the
raw incoming request (e.g., an Envoy `CheckRequest`). MPE then evaluates the
tuple against the active PolicyDomain.

### Multi-phase evaluation

MPE evaluates a PORC tuple in up to four sequential phases. Each phase can
return `allow = 1` (permit), `allow = -1` (deny), or `allow = 0` (pass to
next phase).

1. **Operation policy** — Matched by the `operations` selector; filters
   requests that need no further evaluation (e.g., public endpoints).
2. **Identity policy** — Matched by the caller's assigned **Role**; checks
   principal attributes.
3. **Resource policy** — Matched by the resource's **Resource-Group**; checks
   resource attributes and ownership.
4. **Scope policy** — Matched by the OAuth2 **Scope** presented; limits the
   effective permission to what the client was delegated.

The final decision is `allow` if every phase that produces a conclusive result
agrees to permit, and `deny` if any phase returns `-1`.

---

## PolicyDomain YAML Structure

A **PolicyDomain** is a self-contained YAML bundle that groups all policy
artefacts for a given authorization domain. The Kubernetes-style manifest
format is used:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4   # or v1beta1
kind: PolicyDomain
metadata:
  name: my-domain

spec:
  # ── Reusable Rego libraries ───────────────────────────────────────────────
  policy-libraries:
    - mrn: &utils "mrn:iam:library:utils"
      name: utils
      rego: |
        package utils
        ro_operations := {"*:get", "*:read", "*:list"}

  # ── Policies (Rego modules that produce `allow`) ──────────────────────────
  policies:
    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = true

    - mrn: &read-only "mrn:iam:policy:read-only"
      name: read-only
      dependencies:
        - *utils          # YAML anchor reference to the library above
      rego: |
        package authz
        import data.utils
        default allow = false
        allow { utils.ro_operations[input.operation] }

  # ── Roles (map a principal to a policy) ───────────────────────────────────
  roles:
    - mrn: &admin-role "mrn:iam:role:admin"
      name: admin
      policy: *allow-all

  # ── Groups (bundle roles together) ────────────────────────────────────────
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      roles:
        - *admin-role

  # ── Resource-groups (apply a policy to a class of resources) ─────────────
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      default: true          # used when a resource has no explicit group
      policy: *allow-all

  # ── Scopes (OAuth2 scope → policy mapping) ────────────────────────────────
  scopes:
    - mrn: "mrn:iam:scope:api"
      name: api
      policy: *allow-all

  # ── Operations (match on operation string → policy for phase 1) ───────────
  operations:
    - name: api
      selector:
        - ".*"              # RE2 regex matched against input.operation
      policy: *allow-all

  # ── Mappers (extract PORC from raw request) ───────────────────────────────
  mappers:
    - name: default-mapper
      selector:
        - ".*"              # matched against calling service-account name
      rego: |
        package mapper
        import rego.v1

        porc := {
          "principal": claims,
          "operation": sprintf("%s:http:%s", [service, method]),
          "resource":  {"id": path, "group": "mrn:iam:resource-group:default"},
          "context":   input,
        }
        # ... (extract claims, method, path from input.request.http)
```

### Key YAML conventions

- **MRN** (Manetu Resource Name): a namespaced URN identifying every artefact.
  Format: `mrn:iam:<type>:<name>`. Must be globally unique within a domain.
- **YAML anchors** (`&name`) and aliases (`*name`) are used extensively to wire
  policies to roles, resource-groups, and scopes without repeating MRN strings.
- **`selector`** fields under `operations` and `mappers` contain
  [RE2](https://github.com/google/re2/wiki/Syntax) regex strings. Multiple
  selectors are OR-ed together.
- Policies must define `package authz` and produce a rule named `allow`.
- Libraries use any package name and are imported via `data.<package>` in
  dependent policies.
- Mappers must define `package mapper` and produce a rule named `porc`.

### Supported API versions

| apiVersion | Notes |
|------------|-------|
| `iamlite.manetu.io/v1alpha3` | Stable, widely used |
| `iamlite.manetu.io/v1alpha4` | Adds `resource-groups` top-level key |
| `iamlite.manetu.io/v1beta1` | Adds annotation support for principals |

---

## Key CLI Commands

### `mpe lint`

Validates one or more PolicyDomain files without running policies.

```bash
# Lint a single file
mpe lint -f my-domain.yml

# Lint multiple files (glob)
mpe lint -f "domains/*.yml"
```

Checks performed:
- Valid YAML syntax and schema conformance
- All MRN references resolve within the domain
- All Rego modules parse and compile cleanly (via OPA)
- Selector strings are valid RE2 regex
- Required fields are present

Exit code `0` = clean; non-zero = errors printed to stderr.

### `mpe test`

Runs decision tests against a PolicyDomain bundle.

```bash
# Run all decision tests defined in a test file
mpe test decision -b my-domain.yml -t tests.yaml

# Pipe a single PORC JSON and check the decision
echo '{"principal":{},"operation":"svc:http:get","resource":{"id":"/","group":"mrn:iam:resource-group:default"}}' \
  | mpe test decision -b my-domain.yml
```

Test file format (`tests.yaml`):

```yaml
- description: "admin can read"
  input:
    principal: {sub: "alice", role: "mrn:iam:role:admin"}
    operation: "petstore:http:get"
    resource: {id: "/pets/1", group: "mrn:iam:resource-group:default"}
  expected: allow
```

### `mpe serve`

Starts a local gRPC/HTTP server that evaluates PORC decisions.

```bash
# Serve on the default port (9191)
mpe serve -b my-domain.yml

# Custom port and host
mpe serve -b my-domain.yml --addr 0.0.0.0:8080
```

The server exposes an Envoy `ext_authz` compatible HTTP endpoint at `/check`
and a gRPC endpoint implementing the same interface.

### `mpe build`

Compiles and bundles a PolicyDomain into an OPA bundle (`.tar.gz`).

```bash
mpe build -f my-domain.yml -o bundle.tar.gz
```

---

## Common Patterns

### Allow-all bootstrap policy

Use as a placeholder while developing; replace with fine-grained policy later.

```rego
package authz
default allow = true
```

### JWT-gated identity check

```rego
package authz
default allow = 0   # 0 = pass to next phase

allow = -1 { input.principal == {} }   # deny unauthenticated
```

### Read-only resource policy

```rego
package authz
import data.utils

default allow = false
allow { utils.ro_operations[input.operation] }
```

### Mapper skeleton (Envoy/JWT)

```rego
package mapper
import rego.v1

auth  := input.request.http.headers.authorization
token := split(auth, "Bearer ")[1]
claims := io.jwt.decode(token)[1]

method  := lower(input.request.http.method)
service := "my-service"
path    := input.request.http.path

porc := {
  "principal": claims,
  "operation": sprintf("%s:http:%s", [service, method]),
  "resource":  {"id": path, "group": "mrn:iam:resource-group:default"},
  "context":   input,
}
```

---

## Quick-reference: PolicyDomain spec keys

| Key | Type | Purpose |
|-----|------|---------|
| `policy-libraries` | list | Reusable Rego helpers; imported via `data.<pkg>` |
| `policies` | list | Rego modules producing `allow`; assigned to roles/groups/scopes |
| `roles` | list | Bind a principal to a policy for identity-phase evaluation |
| `groups` | list | Bundle multiple roles |
| `resource-groups` | list | Bind a resource class to a policy for resource-phase evaluation |
| `scopes` | list | Bind an OAuth2 scope to a policy for scope-phase evaluation |
| `operations` | list | Match operations by regex → policy for phase-1 evaluation |
| `mappers` | list | Translate raw requests into PORC tuples |
