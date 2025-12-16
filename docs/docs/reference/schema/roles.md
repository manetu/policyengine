---
sidebar_position: 4
---

# Roles Schema

## Definition

```yaml
spec:
  roles:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      policy: string        # Required: Policy MRN
      annotations: object   # Optional: Key-value metadata
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Role description |
| `policy` | string | Yes | MRN of policy to apply |
| `annotations` | object | No | Custom metadata |

## Usage

Roles are assigned to principals via the `mroles` claim in the JWT. When a principal has a role, the role's policy is evaluated during Phase 2 (identity phase).

## Examples

### Basic Roles

```yaml
roles:
  - mrn: "mrn:iam:role:admin"
    name: admin
    description: "Full administrative access"
    policy: "mrn:iam:policy:allow-all"

  - mrn: "mrn:iam:role:viewer"
    name: viewer
    description: "Read-only access"
    policy: "mrn:iam:policy:read-only"

  - mrn: "mrn:iam:role:no-access"
    name: no-access
    description: "No access - for suspended accounts"
    policy: "mrn:iam:policy:deny-all"
```

### With Annotations

```yaml
roles:
  - mrn: "mrn:iam:role:regional-admin"
    name: regional-admin
    description: "Admin for specific region"
    policy: "mrn:iam:policy:regional-access"
    annotations:
      region: "us-west"
      level: "2"
```

### Using YAML Anchors

```yaml
policies:
  - mrn: &allow-all "mrn:iam:policy:allow-all"
    name: allow-all
    rego: |
      package authz
      default allow = true

roles:
  - mrn: "mrn:iam:role:admin"
    name: admin
    policy: *allow-all
```
