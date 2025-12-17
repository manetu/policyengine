---
sidebar_position: 10
---

# Policies

**Policies** are executable documents expressed in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) programming language that govern access to resources.

## Overview

A policy receives a [PORC expression](/concepts/porc) as input and returns a decision. The output format depends on which phase the policy serves:

| Phase | Output Type | Values |
|-------|-------------|--------|
| Operation (Phase 1) | Integer | Negative (DENY), `0` (GRANT), Positive (GRANT Override) |
| Identity (Phase 2) | Boolean | `true` (GRANT), `false` (DENY) |
| Resource (Phase 3) | Boolean | `true` (GRANT), `false` (DENY) |
| Scope (Phase 4) | Boolean | `true` (GRANT), `false` (DENY) |

## Policy Structure

Every policy must:

1. Declare `package authz`
2. Export an `allow` variable

### Boolean Policy (Identity, Resource, Scope Phases)

Most policies use boolean output:

```rego
package authz

default allow = false

allow {
    # Conditions that grant access
    input.principal.sub != ""
}
```

### Tri-Level Policy (Operation Phase)

Operation phase policies use **tri-level integer output** (negative, zero, positive). A negative outcome is equivalent to DENY and a zero outcome is equivalent to GRANT in other phases. A **positive value acts as a "GRANT Override"** that bypasses all other phases.

```rego
package authz

# Return codes:
#  Negative (e.g., -1): Deny (same as any phase denying)
#  Zero (0): Grant (same as any phase granting); other phases still evaluated
#  Positive (e.g., 1): GRANT Override - immediately grant, skip all other phases
default allow = 0

# Deny if no valid principal on protected endpoints
allow = -1 {
    input.principal == {}
    not is_public_operation
}

# GRANT Override for public operations (bypass identity phase)
allow = 1 {
    is_public_operation
}

is_public_operation {
    input.operation in {"public:health:check", "public:docs:read"}
}
```

**Why tri-level?** Public endpoints have no JWT by definition, so the identity phase would always deny them (no roles = no GRANT). The operation phase's ability to return a positive value (GRANT Override) bypasses the other phases entirely.

**Note**: The specific integer value can serve as a reason code for auditing. The sign determines behavior; the magnitude provides context.

See [Policy Conjunction](/concepts/policy-conjunction#operation-phase-tri-level-policies) for detailed explanation.

## Policy Inputs

All PORC fields are available via `input`:

```rego
package authz

default allow = false

# Access principal attributes
allow {
    input.principal.sub == "admin"
}

# Access operation
allow {
    input.operation == "api:data:read"
}

# Access resource attributes
allow {
    input.resource.owner == input.principal.sub
}

# Access context
allow {
    input.context.source_ip == "10.0.0.1"
}
```

## Common Policy Patterns

### Role-Based Access

```rego
package authz

default allow = false

admin_roles := {
    "mrn:iam:role:admin",
    "mrn:iam:role:superadmin"
}

allow {
    some role in input.principal.mroles
    role in admin_roles
}
```

### Operation-Based Access

```rego
package authz

default allow = false

# Allow read operations
allow {
    endswith(input.operation, ":read")
}

# Allow specific operations
allow {
    input.operation in {
        "api:users:list",
        "api:users:get"
    }
}

# Glob matching
allow {
    glob.match("api:*:read", [], input.operation)
}
```

### Owner-Based Access

```rego
package authz

default allow = false

# Only owner can access
allow {
    input.principal.sub == input.resource.owner
}
```

### Clearance-Based Access

```rego
package authz

default allow = false

ratings := {
    "LOW": 1,
    "MODERATE": 2,
    "HIGH": 3,
    "MAXIMUM": 4
}

allow {
    ratings[input.principal.mclearance] >= ratings[input.resource.classification]
}
```

### Time-Based Access

```rego
package authz

default allow = false

# Only allow during business hours
allow {
    time.clock(time.now_ns()) >= [9, 0, 0]
    time.clock(time.now_ns()) <= [17, 0, 0]
}
```

## Using Dependencies

Import libraries declared as dependencies:

```yaml
policies:
  - mrn: "mrn:iam:policy:my-policy"
    name: my-policy
    dependencies:
      - "mrn:iam:library:helpers"
    rego: |
      package authz
      import data.helpers

      default allow = false

      allow {
          helpers.is_admin(input.principal)
      }
```

## Policy Definition in YAML

```yaml
policies:
  - mrn: "mrn:iam:policy:example"
    name: example
    description: "Example policy with full features"
    public: true  # Optional: mark as public
    dependencies:
      - "mrn:iam:library:utils"
    rego: |
      package authz
      import data.utils

      default allow = false

      allow {
          utils.check_something(input)
      }
```

## Best Practices

1. **Default to deny**: Always use `default allow = false`
2. **Be explicit**: Clear conditions are easier to audit
3. **Use libraries**: Extract reusable logic
4. **Test thoroughly**: Cover both grant and deny cases
5. **Document decisions**: Comment complex logic

## Related Concepts

- **[Policy Conjunction](/concepts/policy-conjunction)**: How policies from different phases combine
- **[Policy Libraries](/concepts/policy-libraries)**: Reusable Rego code for policies
- **[PORC](/concepts/porc)**: The input format for policy evaluation
- **[Operations](/concepts/operations)**: Route requests to operation phase policies
- **[Roles](/concepts/roles)**: Connect principals to identity phase policies
- **[Resource Groups](/concepts/resource-groups)**: Connect resources to resource phase policies
- **[Scopes](/concepts/scopes)**: Connect access methods to scope phase policies
- **[Policy Domains](/concepts/policy-domains)**: Container for policy definitions
