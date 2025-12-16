---
sidebar_position: 7
---

# Scopes Schema

Scopes define access-method constraints that apply additional policy evaluation during Phase 4. For conceptual understanding, see [Scopes](/concepts/scopes).

## Definition

```yaml
spec:
  scopes:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      policy: string        # Required: Policy MRN
      annotations:          # Optional: Key-value metadata
        - name: string
          value: string     # JSON-encoded value
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable scope name |
| `description` | string | No | Scope description |
| `policy` | string | Yes | MRN of policy to apply |
| `annotations` | array | No | List of name/value objects for custom metadata |

## Usage

Scopes define constraint boundaries based on access method. When a request includes scopes (via `context.scopes` in the PORC), the scope policies are evaluated during Phase 4 (scope phase). Common sources of scopes include:

- Personal Access Tokens (PATs)
- Federated identity sessions
- OAuth token claims
- Service-to-service authentication contexts

## Examples

### Basic Scopes

```yaml
scopes:
  - mrn: "mrn:iam:scope:read-only"
    name: read-only
    description: "Restricts to read operations only"
    policy: "mrn:iam:policy:read-only-check"

  - mrn: "mrn:iam:scope:internal"
    name: internal
    description: "Internal system access"
    policy: "mrn:iam:policy:internal-only"

  - mrn: "mrn:iam:scope:admin"
    name: admin
    description: "Administrative operations"
    policy: "mrn:iam:policy:admin-only"
```

### With Annotations

```yaml
scopes:
  - mrn: "mrn:iam:scope:pii"
    name: pii
    description: "Access to PII data"
    policy: "mrn:iam:policy:pii-access"
    annotations:
      - name: "sensitivity"
        value: "\"high\""
      - name: "audit"
        value: "true"
```

### Using YAML Anchors

```yaml
policies:
  - mrn: &read-only "mrn:iam:policy:read-only"
    name: read-only
    rego: |
      package authz
      # ... read-only policy

scopes:
  - mrn: "mrn:iam:scope:viewer"
    name: viewer
    policy: *read-only
```

## Scope Evaluation

Scopes are evaluated in Phase 4. Within the scope phase:

- If no scopes are present in the PORC, the phase defaults to **GRANT**
- If scopes are present, at least one scope policy must vote **GRANT** for the phase to pass
- Multiple scope policies use OR logic (any GRANT is sufficient)

For complete details on how scopes interact with other phases, see [Policy Conjunction](/concepts/policy-conjunction).
