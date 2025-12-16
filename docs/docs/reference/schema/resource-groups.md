---
sidebar_position: 6
---

# Resource Groups Schema

## Definition

```yaml
spec:
  resource-groups:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      default: boolean      # Optional: Is default group (default: false)
      policy: string        # Required: Policy MRN
      annotations:          # Optional: Key-value metadata
        - name: string
          value: string     # JSON-encoded value
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Resource group description |
| `default` | boolean | No | Use as default for unassigned resources |
| `policy` | string | Yes | MRN of policy to apply |
| `annotations` | array | No | List of name/value objects for custom metadata |

## Usage

Resource groups associate policies with resources. When a resource specifies a group, that group's policy is evaluated during Phase 3 (resource phase).

## Examples

### Basic Resource Groups

```yaml
resource-groups:
  - mrn: "mrn:iam:resource-group:public"
    name: public
    description: "Publicly accessible resources"
    policy: "mrn:iam:policy:allow-all"

  - mrn: "mrn:iam:resource-group:default"
    name: default
    description: "Default for authenticated access"
    default: true
    policy: "mrn:iam:policy:authenticated-only"

  - mrn: "mrn:iam:resource-group:sensitive"
    name: sensitive
    description: "Requires elevated permissions"
    policy: "mrn:iam:policy:clearance-required"
```

### With Annotations

```yaml
resource-groups:
  - mrn: "mrn:iam:resource-group:pii-data"
    name: pii-data
    description: "Personally identifiable information"
    policy: "mrn:iam:policy:pii-access"
    annotations:
      - name: "compliance"
        value: "\"GDPR\""
      - name: "retention_days"
        value: "365"
      - name: "audit_required"
        value: "true"
```

### Using YAML Anchors

```yaml
policies:
  - mrn: &share-policy "mrn:iam:policy:share-by-clearance"
    name: share-by-clearance
    rego: |
      package authz
      # ... clearance-based policy

resource-groups:
  - mrn: "mrn:iam:resource-group:classified"
    name: classified
    policy: *share-policy
```

## Default Resource Group

Mark one resource group as `default: true` to apply it to resources that don't specify a group:

```yaml
resource-groups:
  - mrn: "mrn:iam:resource-group:default"
    name: default
    default: true
    policy: "mrn:iam:policy:authenticated-only"
```
