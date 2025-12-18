---
sidebar_position: 4
---

# Operations

**Operations** define the actions that can be performed in your system and route requests to the appropriate policies.

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
      policy: "mrn:iam:policy:allow-all"
```

## Selectors

Selectors are regular expressions that match operation strings:

```yaml
operations:
  # Match exact operations first
  - name: health-check
    selector:
      - "^system:health:check$"
    policy: "mrn:iam:policy:allow-all"

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

No authentication required:

```yaml
operations:
  - name: public
    selector:
      - "public:.*"
      - "health:.*"
    policy: "mrn:iam:policy:allow-all"
```

### User Operations

Requires authenticated user:

```yaml
operations:
  - name: user-ops
    selector:
      - "user:.*"
    policy: "mrn:iam:policy:user-authenticated"
```

### Admin Operations

Requires admin role:

```yaml
operations:
  - name: admin-ops
    selector:
      - "admin:.*"
      - "platform:.*"
    policy: "mrn:iam:policy:admin-only"
```

## Best Practices

1. **Use consistent naming**: Follow `subsystem:resource:verb` pattern
2. **Order selectors carefully**: Put specific matches before general ones
3. **Document operations**: Keep a reference of available operations
4. **Use verbs consistently**: `create`, `read`, `update`, `delete`, `list`
5. **Avoid overlapping selectors**: Make patterns mutually exclusive when possible

## Related Concepts

- **[Policies](/concepts/policies)**: The Rego code that operations route to
- **[Policy Conjunction](/concepts/policy-conjunction)**: How operation policies fit into Phase 1 evaluation
- **[PORC](/concepts/porc)**: The `operation` field in authorization requests
- **[Policy Domains](/concepts/policy-domains)**: Where operations are defined
