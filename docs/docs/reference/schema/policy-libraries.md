---
sidebar_position: 3
---

# Policy Libraries Schema

## Definition

```yaml
spec:
  policy-libraries:
    - mrn: string           # Required: MRN identifier
      name: string          # Required: Human-readable name
      description: string   # Optional: Description
      dependencies: []      # Optional: Other library dependencies
      rego: string          # Required: Rego code (or rego_filename)
      rego_filename: string # Alternative: External file path
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mrn` | string | Yes | Unique MRN identifier |
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Library description |
| `dependencies` | array | No | List of other library MRNs |
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

Libraries should:
- Use a unique package name (not `authz`)
- Export functions or data for policies to use

## Examples

### Basic Library

```yaml
policy-libraries:
  - mrn: "mrn:iam:library:utils"
    name: utils
    description: "Common utility functions"
    rego: |
      package utils

      match_any(patterns, value) {
          glob.match(patterns[_], [], value)
      }

      ro_operations := {
          "*:read", "*:list", "*:get"
      }
```

### Library with Dependencies

```yaml
policy-libraries:
  - mrn: &utils "mrn:iam:library:utils"
    name: utils
    rego: |
      package utils
      ro_operations := {"*:read", "*:list"}

  - mrn: "mrn:iam:library:access"
    name: access
    dependencies:
      - *utils
    rego: |
      package access
      import data.utils

      is_readonly {
          utils.match_any(utils.ro_operations, input.operation)
      }
```

### Using in Policies

```yaml
policies:
  - mrn: "mrn:iam:policy:viewer"
    name: viewer
    dependencies:
      - "mrn:iam:library:access"
    rego: |
      package authz
      import data.access

      default allow = false
      allow { access.is_readonly }
```
