---
sidebar_position: 4
---

# Operations

**Operations** define the actions that can be performed in your system and route requests to the appropriate policies, and are evaluated during Phase 1 (Operation Phase) of [Policy Conjunction](/concepts/policy-conjunction).


## Overview

Operations serve two purposes:

1. **Identification**: Normalize action identifiers across your system
2. **Routing**: Select which policy evaluates requests for specific operations

## Operation Format

Operations typically follow the format:

```
<subsystem>:<resource-class>:<verb>
```

### Examples

| Operation | Description |
|-----------|-------------|
| `iam:identity:create` | Create an identity in IAM |
| `vault:attributes:read` | Read attributes from vault |
| `api:users:list` | List users via API |
| `realm:metadata:update` | Update realm metadata |
| `graphql:query` | Execute GraphQL query |

## Defining Operations

Operations are defined in the PolicyDomain `spec.operations` section:

```yaml
spec:
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

    - name: public
      selector:
        - "public:.*"
      policy: "mrn:iam:policy:public-grant"
```

## Selectors

Selectors are regular expressions that match operation strings:

```yaml
operations:
  # Match exact operations first
  - name: health-check
    selector:
      - "^system:health:check$"
    policy: "mrn:iam:policy:public-grant"

  # Match specific patterns
  - name: vault-ops
    selector:
      - "vault:.*:read"
      - "vault:.*:list"
    policy: "mrn:iam:policy:vault-readonly"

  # Catch-all last
  - name: default
    selector:
      - ".*"
    policy: "mrn:iam:policy:default"
```

:::note[Multiple Selectors]
When an operation entry contains multiple selectors, they have an **OR** relationship. The operation matches if **any** of its selectors match. For example, `vault-ops` above matches requests for either `vault:.*:read` OR `vault:.*:list`. This OR behavior applies uniformly to all selector-based entities (operations, resources, and mappers).
:::

### Selector Order

Operations are evaluated **in order**. The first matching selector wins:

```yaml
operations:
  # Specific match first
  - name: admin-read
    selector:
      - "admin:.*:read"
    policy: "mrn:iam:policy:admin-readonly"

  # Then broader match
  - name: admin-all
    selector:
      - "admin:.*"
    policy: "mrn:iam:policy:admin-full"

  # Catch-all last
  - name: default
    selector:
      - ".*"
    policy: "mrn:iam:policy:default"
```

## Using Operations in Policies

Access the operation in Rego via `input.operation`:

```rego
package authz

default allow = false

# Allow specific operations
allow {
    input.operation in allowed_operations
}

allowed_operations := {
    "api:users:read",
    "api:users:list"
}

# Pattern matching
allow {
    glob.match("*:*:read", [], input.operation)
}

# Parse operation components
allow {
    parts := split(input.operation, ":")
    parts[0] == "api"
    parts[2] == "read"
}
```

## Common Operation Categories

### Public Operations

No authentication required—uses a [tri-level](/concepts/policies#tri-level) GRANT override to bypass identity and resource phases:

```yaml
operations:
  - name: public
    selector:
      - "public:.*"
      - "health:.*"
    policy: "mrn:iam:policy:public-grant"
```

### User Operations

Denies unauthenticated requests, then defers to identity and resource phases:

```yaml
operations:
  - name: user-ops
    selector:
      - "user:.*"
    policy: "mrn:iam:policy:require-auth"
```

### Admin Operations

Denies unauthenticated requests and verifies admin access:

```yaml
operations:
  - name: admin-ops
    selector:
      - "admin:.*"
      - "platform:.*"
    policy: "mrn:iam:policy:require-admin"
```

## Best Practices

1. **Use consistent naming**: Follow `subsystem:resource:verb` pattern
2. **Use domain prefixes for clarity**: When integrating multiple systems, use unique prefixes (e.g., `mcp:tool:call`, `api:users:read`) to enable meaningful policy checks based on operation origin
3. **Order selectors carefully**: Put specific matches before general ones
4. **Document operations**: Keep a reference of available operations
5. **Use verbs consistently**: `create`, `read`, `update`, `delete`, `list`
6. **Avoid overlapping selectors**: Make patterns mutually exclusive when possible

### Operation Prefixes for Multi-Domain Policies

When your PolicyDomain integrates multiple systems or protocols, use distinct prefixes to enable meaningful identity phase checks:

```yaml
# MCP protocol operations
operations:
  - name: mcp-operations
    selector:
      - "mcp:.*"
    policy: *policy-mcp-operation

# API operations
  - name: api-operations
    selector:
      - "api:.*"
    policy: *policy-api-operation
```

This allows identity policies to check the operation prefix and apply appropriate rules:

```rego
package authz

import rego.v1

default allow = false

# Allow MCP operations for MCP users
allow if {
    startswith(input.operation, "mcp:")
    "mrn:iam:role:mcp-user" in input.principal.mroles
}

# Allow API operations for API users
allow if {
    startswith(input.operation, "api:")
    "mrn:iam:role:api-user" in input.principal.mroles
}
```

Without prefixes, the identity policy would have no way to distinguish which system the operation belongs to.

## Related Concepts

- **[Policies](/concepts/policies)**: The Rego code that operations route to
- **[Policy Conjunction](/concepts/policy-conjunction)**: How operation policies fit into Phase 1 evaluation
- **[PORC](/concepts/porc)**: The `operation` field in authorization requests
- **[Policy Domains](/concepts/policy-domains)**: Where operations are defined
