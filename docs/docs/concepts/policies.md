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

Operation phase policies use **tri-level integer output** instead of boolean:

```rego
package authz

default allow = 0  # Continue to other phases

allow = 1 { is_public_operation }     # GRANT Override (bypass other phases)
allow = -1 { input.principal == {} }  # Deny

is_public_operation {
    input.operation in {"public:health:check", "public:docs:read"}
}
```

The GRANT Override (positive value) is essential for public endpoints that have no JWT—without it, the identity phase would always deny them. See [Tri-Level Policies](/concepts/policy-conjunction#tri-level) for complete semantics, return value meanings, and usage guidance.

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

# Only the owner can access
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

## Authoring Policies for Different Phases

While all four phases (operation, identity, resource, scope) evaluate Rego policies drawn from the same pool of Policy entities, the **goals of each phase are different**. Understanding these differences helps you write cleaner, more maintainable policies.

### Operation Phase (Phase 1): Coarse-Grained Request Control

Operation phase policies focus on **request-level requirements** that apply regardless of specific resources or detailed identity attributes:

- Validating that a JWT is present for protected endpoints
- Identifying public endpoints that require no authentication
- Implementing IP allowlists/blocklists
- Rejecting requests that fail basic sanity checks

```rego
package authz

default allow = 0  # Continue to other phases

# Public endpoints bypass identity/resource phases
allow = 1 {
    input.operation in {"public:health:check", "public:docs:read"}
}

# Reject unauthenticated requests to protected endpoints
allow = -1 {
    input.principal == {}
}
```

**Key insight**: Operation policies answer "Should this request be processed at all?" rather than "Does this specific principal have access to this specific resource?"

### Identity Phase (Phase 2): Principal-Centric Permissions

Identity phase policies focus on **what operations the principal is permitted to perform** based on their identity attributes (roles, groups, claims). These policies consider the principal and the operation, but generally **do not concern themselves with resource-specific logic**—that's the resource phase's job.

Since each role references its own policy, you'll typically have separate policies for different roles:

**Editor role policy** (`mrn:iam:policy:editor-operations`):
```rego
package authz

default allow = false

# Editors can create, update, and read content
permitted_operations := {
    "api:documents:create",
    "api:documents:update",
    "api:documents:read",
    "api:documents:list",
}

allow {
    input.operation in permitted_operations
}
```

**Viewer role policy** (`mrn:iam:policy:viewer-operations`):
```rego
package authz

default allow = false

# Viewers can only perform read-like operations
permitted_operations := {
    "*:read",
    "*:list",
    "*:get",
}

allow {
    glob.match(permitted_operations[_], [], input.operation)
}
```

**Key insight**: Identity policies answer "Based on who this principal is, what types of operations can they perform?" The resource phase will separately determine whether the principal can access the *specific* resource.

### Resource Phase (Phase 3): Resource-Centric Access Control

Resource phase policies focus on **what properties the principal must have to access this specific resource**. These policies often compare principal attributes against resource attributes:

```rego
package authz

default allow = false

# Owner has full access
allow {
    input.principal.sub == input.resource.owner
}

# Non-owners can only perform read-like operations
readonly_operations := {
    "*:read",
    "*:list",
    "*:get",
}

allow {
    input.principal.sub != input.resource.owner
    glob.match(readonly_operations[_], [], input.operation)
}
```

Another common pattern is **clearance-based access**, where principal attributes are compared against resource classification:

```rego
package authz

default allow = false

clearance_level(c) = 1 { c == "PUBLIC" }
clearance_level(c) = 2 { c == "INTERNAL" }
clearance_level(c) = 3 { c == "CONFIDENTIAL" }
clearance_level(c) = 4 { c == "SECRET" }

allow {
    clearance_level(input.principal.mclearance) >= clearance_level(input.resource.classification)
}
```

**Key insight**: Resource policies answer "Given this principal's attributes and this resource's attributes, should access be granted?" They may also consider the operation to implement tiered access (e.g., owners get full access, others get read-only).

### Scope Phase (Phase 4): Access Method Constraints

Scope phase policies focus on **constraining access based on how the request was authenticated** (PATs, OAuth tokens, federated sessions). These policies typically restrict operations regardless of identity or resource:

```rego
package authz

default allow = false

# Read-only scope permits only read-like operations
permitted_operations := {
    "*:read",
    "*:list",
    "*:get",
    "*:query",
}

allow {
    glob.match(permitted_operations[_], [], input.operation)
}
```

**Key insight**: Scope policies answer "Given the access method (token type, federation context), is this operation permitted?" They act as an additional constraint layer.

### Avoid Duplicating Logic Across Phases

A common anti-pattern is duplicating the same checks across multiple phases. This makes policies harder to maintain and debug:

```rego
# ❌ Bad: Checking authentication in every phase
# operation_policy.rego
allow = -1 { input.principal == {} }

# identity_policy.rego
allow { input.principal.sub != "" }  # Redundant auth check

# resource_policy.rego
allow { input.principal.sub != "" }  # Redundant again
```

Instead, **handle each concern in the appropriate phase**:

```rego
# ✅ Good: Authentication checked once in operation phase
# operation_policy.rego
allow = -1 { input.principal == {} }  # Only check here

# identity_policy.rego - assumes principal is authenticated
allow { input.operation in allowed_operations }

# resource_policy.rego - assumes principal is authenticated
allow { input.principal.sub == input.resource.owner }
```

### Avoid Using the Same Policy in Multiple Phases

Another anti-pattern is referencing the same policy MRN from both identity (roles) and resource (resource-groups) configurations. This typically indicates the policy is trying to do too much:

```yaml
# ❌ Bad: Same policy used in both phases
roles:
  - mrn: "mrn:iam:role:editor"
    policy: "mrn:iam:policy:mega-policy"  # Does everything

resource-groups:
  - mrn: "mrn:iam:resource-group:documents"
    policy: "mrn:iam:policy:mega-policy"  # Same policy!
```

This approach leads to unwieldy policies that mix concerns and are difficult to understand. Instead, write focused policies for each phase:

```yaml
# ✅ Good: Separate, focused policies
roles:
  - mrn: "mrn:iam:role:editor"
    policy: "mrn:iam:policy:editor-operations"  # What editors can do

resource-groups:
  - mrn: "mrn:iam:resource-group:documents"
    policy: "mrn:iam:policy:document-access"  # How documents are accessed
```

### Summary: Phase Responsibilities

| Phase | Focus | Typical Checks |
|-------|-------|----------------|
| **Operation** | Request validity | Authentication present, public endpoints, IP filtering |
| **Identity** | Principal capabilities | Which operations this principal can perform |
| **Resource** | Resource access rules | Principal-to-resource relationship (ownership, clearance) |
| **Scope** | Access method constraints | Token type limitations (read-only PAT, OAuth scopes) |

By keeping each phase focused on its specific concern, you create policies that are easier to write, test, audit, and maintain.

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