---
sidebar_position: 2
---

# Policies Schema

## Definition

```yaml
spec:
  policies:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      public: boolean       # Optional: Mark as public (default: false)
      dependencies: []      # Optional: Library dependencies
      rego: string          # Required: Rego code (or rego_filename)
      rego_filename: string # Alternative: External file path
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Policy description |
| `public` | boolean | No | Whether policy is public |
| `dependencies` | array | No | List of library MRNs |
| `rego` | string | See below | Inline Rego code |
| `rego_filename` | string | See below | Path to external `.rego` file |

### Rego Code Fields

The `rego` and `rego_filename` fields specify where the Rego code comes from:

| Document Kind | `rego` | `rego_filename` |
|---------------|--------|-----------------|
| `PolicyDomain` | Required | Not supported |
| `PolicyDomainReference` | Optional | Optional |

For `PolicyDomainReference`, you must provide either `rego` (inline) or `rego_filename` (external file), but not both. Using `rego_filename` is recommended for development as it enables IDE syntax highlighting and cleaner version control diffs.

See [PolicyDomain vs PolicyDomainReference](/reference/schema/#policydomain-vs-policydomainreference) for more details.

## Rego Requirements

Every policy must:

1. Declare `package authz`
2. Export `allow` variable

### Boolean Policy

```yaml
rego: |
  package authz
  default allow = false
  allow { ... }
```

### Tri-Level Policy (Operation Phase)

Operation phase policies use integer output instead of boolean. Negative values are DENY, zero is GRANT (other phases still evaluated), and positive values are GRANT Override (bypassing other phases):

```yaml
rego: |
  package authz
  default allow = 0
  allow = -1 { input.principal == {} }  # Deny
  allow = 1 { is_public_operation }     # GRANT Override
```

See [Tri-Level Policies](/concepts/policies#tri-level) for complete semantics and usage guidance.

## Examples

### Simple Policy

```yaml
policies:
  - mrn: "mrn:iam:policy:allow-all"
    name: allow-all
    description: "Grants all access"
    rego: |
      package authz
      default allow = true
```

### Policy with Dependencies

```yaml
policies:
  - mrn: "mrn:iam:policy:read-only"
    name: read-only
    dependencies:
      - "mrn:iam:library:utils"
    rego: |
      package authz
      import data.utils

      default allow = false
      allow {
          utils.is_read_operation(input.operation)
      }
```

### Using External File

```yaml
# In PolicyDomainReference
policies:
  - mrn: "mrn:iam:policy:main"
    name: main
    rego_filename: policies/main.rego
```

### Operation Phase Policy

```yaml
policies:
  - mrn: "mrn:iam:policy:operations"
    name: operations
    description: "Operation phase policy for request routing"
    rego: |
      package authz
      default allow = 0  # Tri-level: negative=DENY, 0=GRANT, positive=GRANT Override

      # Deny unauthenticated requests on protected endpoints
      allow = -1 {
          input.principal == {}
          not input.operation in public_operations
      }

      # Grant for public operations (bypasses identity phase)
      allow = 1 {
          input.operation in public_operations
      }

      public_operations := {
          "public:health:check",
          "public:docs:read"
      }
```
