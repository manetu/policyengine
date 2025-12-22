---
sidebar_position: 8
---

# Operations Schema

## Definition

```yaml
spec:
  operations:
    - name: string          # Required: Human-readable name
      selector: []          # Required: Regex patterns to match
      policy: string        # Required: Policy MRN
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name |
| `selector` | array | Yes | List of regex patterns |
| `policy` | string | Yes | MRN of policy to apply |

## Usage

Operations route requests to **operation phase (Phase 1)** policies based on the operation string. Selectors are evaluated in order; first match wins.

The operation phase uses [tri-level output](/concepts/policies#tri-level) (negative, zero, positive) instead of boolean. A positive value acts as a "GRANT Override" that bypasses all other phases—essential for public endpoints that have no JWT.

## Selector Patterns

Selectors are regular expressions using [RE2 syntax](https://github.com/google/re2/wiki/Syntax):

| Pattern | Matches |
|---------|---------|
| `.*` | Everything |
| `api:.*` | Operations starting with `api:` |
| `api:users:.*` | All user operations |
| `^api:users:read$` | Exactly `api:users:read` |
| `api:.*:read` | Read operations on any API resource |

## Examples

### Basic Operations

```yaml
operations:
  - name: api
    selector:
      - "api:.*"
    policy: "mrn:iam:policy:api-main"

  - name: admin
    selector:
      - "admin:.*"
      - "platform:.*"
    policy: "mrn:iam:policy:admin-only"

  - name: default
    selector:
      - ".*"
    policy: "mrn:iam:policy:default"
```

### Order Matters

```yaml
operations:
  # Specific matches first (public-grant returns positive to bypass other phases)
  - name: public-health
    selector:
      - "^health:check$"
    policy: "mrn:iam:policy:public-grant"

  # Then broader patterns
  - name: api-read
    selector:
      - "api:.*:read"
      - "api:.*:list"
    policy: "mrn:iam:policy:api-readonly"

  # Most specific before general
  - name: api-all
    selector:
      - "api:.*"
    policy: "mrn:iam:policy:api-full"

  # Catch-all last (returns 0 to defer to identity/resource phases)
  - name: default
    selector:
      - ".*"
    policy: "mrn:iam:policy:operation-default"
```

### Using YAML Anchors

```yaml
policies:
  - mrn: &main "mrn:iam:policy:main"
    name: main
    rego: |
      package authz
      # ... main policy

operations:
  - name: all
    selector:
      - ".*"
    policy: *main
```
