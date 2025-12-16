---
sidebar_position: 5
---

# Groups Schema

## Definition

```yaml
spec:
  groups:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      roles: []             # Required: List of role MRNs
      annotations:          # Optional: Key-value metadata
        - name: string
          value: string     # JSON-encoded value
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Group description |
| `roles` | array | Yes | List of role MRNs |
| `annotations` | array | No | List of name/value objects for custom metadata |

## Usage

Groups organize roles. When a principal belongs to a group (via `mgroups` claim), they inherit all roles in that group.

## Examples

### Basic Groups

```yaml
groups:
  - mrn: "mrn:iam:group:admins"
    name: admins
    description: "System administrators"
    roles:
      - "mrn:iam:role:admin"

  - mrn: "mrn:iam:group:developers"
    name: developers
    description: "Development team"
    roles:
      - "mrn:iam:role:developer"
      - "mrn:iam:role:viewer"
```

### With Annotations

```yaml
groups:
  - mrn: "mrn:iam:group:finance"
    name: finance
    description: "Finance department"
    roles:
      - "mrn:iam:role:finance-user"
    annotations:
      - name: "department"
        value: "\"finance\""
      - name: "cost_center"
        value: "12345"
```

### Using YAML Anchors

```yaml
roles:
  - mrn: &admin "mrn:iam:role:admin"
    name: admin
    policy: "mrn:iam:policy:allow-all"

  - mrn: &viewer "mrn:iam:role:viewer"
    name: viewer
    policy: "mrn:iam:policy:read-only"

groups:
  - mrn: "mrn:iam:group:power-users"
    name: power-users
    roles:
      - *admin
      - *viewer
```
