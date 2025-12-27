---
sidebar_position: 10
---

# Policies

**Policies** are executable documents expressed in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) programming language that govern access to resources.

## Overview

A policy receives a [PORC expression](/concepts/porc) as input and returns a decision. The output format depends on which phase the policy serves:

| Phase               | Output Type | Values                                                  |
|---------------------|-------------|---------------------------------------------------------|
| Operation (Phase 1) | Integer     | Negative (DENY), `0` (GRANT), Positive (GRANT Override) |
| Identity (Phase 2)  | Boolean     | `true` (GRANT), `false` (DENY)                          |
| Resource (Phase 3)  | Boolean     | `true` (GRANT), `false` (DENY)                          |
| Scope (Phase 4)     | Boolean     | `true` (GRANT), `false` (DENY)                          |

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

Operation phase policies use **tri-level integer output** instead of boolean. The recommended pattern is **default deny** with positive grants:

```rego
package authz

import rego.v1

# Tri-level: negative=DENY, 0=GRANT, positive=GRANT Override
# Default deny - only grant if authenticated or public
default allow = -1

# Helper: check if this is a public operation
is_public if {
    input.operation in {"public:health:check", "public:docs:read"}
}

# Helper: check if request has a valid principal
has_principal if {
    input.principal != {}
    input.principal.sub != ""
}

# Public operations bypass auth (grant-override)
allow = 1 if is_public

# Grant authenticated requests
allow = 0 if has_principal
```

This "default deny" approach is safer and cleaner than using `default allow = 0` with explicit deny rules. The GRANT Override (positive value) is essential for public endpoints that have no JWT—without it, the identity phase would always deny them. See [Tri-Level Policies](#tri-level) below for complete semantics, return value meanings, and usage guidance.

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

### Operation Phase (Phase 1): Tri-Level Policies {#tri-level}

Operation phase policies focus on **request-level requirements** that apply regardless of specific resources or detailed identity attributes:

- Validating that a JWT is present for protected endpoints
- Identifying public endpoints that require no authentication
- Implementing IP allowlists/blocklists
- Rejecting requests that fail basic sanity checks

Unlike other phases that use boolean output, operation phase policies use **tri-level integer output** (negative, zero, positive). A negative outcome is equivalent to DENY, and a zero outcome is equivalent to GRANT. The **positive outcome is unique**: it acts as a "GRANT Override" that bypasses all other phases.

:::tip Terminology
This feature is sometimes called "tri-state" in conversation, referring to the three possible outcomes. The documentation uses "tri-level" to emphasize that the actual output is an integer with magnitude, not just three discrete states—the specific value can serve as a reason code for auditing.
:::

#### Why Tri-Level?

Consider a public health-check endpoint that requires no authentication:

- The caller has no JWT (by design—it's a public endpoint)
- Without a JWT, there are no roles or groups
- The identity phase would vote DENY (no roles = no GRANT)
- The request fails, even though it should succeed

The operation phase's ability to return a **positive value** solves this by granting access immediately, bypassing the identity, resource, and scope phases entirely.

#### Tri-Level Values

Operation phase policies return an integer instead of a boolean:

| Value | Meaning | Effect |
|-------|---------|--------|
| Negative (e.g., `-1`) | **DENY** | Same as any phase voting DENY |
| Zero (`0`) | **GRANT** | Same as any phase voting GRANT; other phases still evaluated |
| Positive (e.g., `1`) | **GRANT Override** | Immediately grant; **skip all other phases** |

:::info Note
The specific integer value can serve as a reason code for auditing purposes. For example, `-1` vs `-2` could indicate different denial reasons, and `1` vs `2` could indicate different bypass scenarios. The sign determines the behavior; the magnitude provides additional context.
:::

#### Example: Public Endpoints

The recommended pattern uses **default deny** with positive grants:

```rego
package authz

import rego.v1

# Tri-level: negative=DENY, 0=GRANT, positive=GRANT Override
# Default deny - only grant if authenticated or public
default allow = -1

# Helper: check if this is a public endpoint
is_public if {
    input.operation in public_operations
}

# Helper: check if request has a valid principal
has_principal if {
    input.principal != {}
    input.principal.sub != ""
}

# Public endpoints bypass auth (grant-override)
allow = 1 if is_public

# Grant authenticated requests
allow = 0 if has_principal

public_operations := {
    "public:health:check",
    "public:docs:read",
    "public:metrics:scrape"
}
```

This approach is cleaner than using `default allow = 0` with explicit deny rules like `allow = -1 { not has_principal; not is_public }`. With default deny, forgetting a grant condition results in denial (safe), whereas with default grant, forgetting a deny condition could allow unauthorized access.

#### When to Use Each Value

| Scenario | Return Value | Rationale |
|----------|--------------|-----------|
| Normal authenticated request | `0` | Grant from operation phase; let identity/resource phases also evaluate |
| Public endpoint (no auth required) | Positive (`1`) | **GRANT Override** — bypass identity phase which would fail |
| Internal service bypass | Positive (`2`) | **GRANT Override** — trusted service, skip detailed checks |
| Missing JWT on protected endpoint | Negative (`-1`) | Deny (same as any phase denying) |
| Known bad actor (IP blocklist) | Negative (`-2`) | Deny with different reason code |

#### Contrast with Other Phases

Other phases (identity, resource, scope) use boolean policies:

```rego
# Identity/Resource/Scope phases - boolean output
package authz

import rego.v1

default allow = false
allow if { ... }  # true or false
```

Only operation phase policies use integer output. The recommended pattern is **default deny**:

```rego
# Operation phase - tri-level integer output (not boolean)
package authz

import rego.v1

# Default deny - safer than default grant
default allow = -1

allow = 1 if { ... }  # GRANT Override (bypass other phases)
allow = 0 if { ... }  # GRANT (other phases still evaluated)
```

#### Audit Visibility

Tri-level outcomes are captured in the [AccessRecord](/concepts/audit) with specific fields that distinguish them from normal GRANT/DENY votes:

| Outcome | AccessRecord Fields |
|---------|---------------------|
| Negative (DENY) | `decision: DENY`, `value` contains the integer (e.g., `-1`, `-2`) |
| Zero (GRANT) | `decision: GRANT`, normal policy outcome |
| Positive (GRANT Override) | `decision: GRANT`, `override: true`, `value` contains the integer |

When a GRANT Override occurs, the AccessRecord also reflects that the identity, resource, and scope phases were **not evaluated**—their references will be absent from the record. This makes it clear in the audit trail that the operation phase short-circuited the evaluation.

Using distinct integer values (e.g., `-1` for missing JWT, `-2` for IP blocklist) provides granular audit visibility without requiring separate policies for each denial reason.

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

## Writing Concise Rego

### Set Iteration Instead of Repeated Rules

Instead of writing multiple separate rules for similar conditions, use set iteration with `some ... in`:

```rego
# ❌ Verbose: Multiple rules for similar patterns
required_permission(op) := "read" if endswith(op, ":read")
required_permission(op) := "read" if endswith(op, ":list")
required_permission(op) := "read" if endswith(op, ":get")

# ✅ Concise: Set iteration
required_permission(op) := "read" if {
    some suffix in {":read", ":list", ":get"}
    endswith(op, suffix)
}
```

This pattern is cleaner, easier to maintain, and performs the same function.

### Meaningful Helper Functions

Extract commonly used checks into well-named helper functions:

```rego
# ✅ Good: Descriptive helper names
is_public if {
    glob.match("api:public:.*", [], input.operation)
}

has_principal if {
    input.principal != {}
    input.principal.sub != ""
}

is_read_only if {
    some pattern in {"*:read", "*:list", "*:get"}
    glob.match(pattern, [], input.operation)
}

# Use helpers in rules
allow = 1 if is_public
allow = 0 if has_principal
```

For helpers used across multiple policies, extract them into a [Policy Library](/concepts/policy-libraries).

## Best Practices

1. **Default to deny**: Use `default allow = false` for boolean policies; use `default allow = -1` for tri-level operation policies
2. **Use default deny for tri-level**: Prefer `default allow = -1` with positive grants over `default allow = 0` with explicit denies—it's safer and cleaner
3. **Extract common helpers**: Move repeated logic like `has_principal` into a shared [Policy Library](/concepts/policy-libraries)
4. **Use set iteration**: Write `some x in {...}` instead of multiple separate rules
5. **Be explicit**: Clear conditions are easier to audit
6. **Test thoroughly**: Cover both grant and deny cases
7. **Document decisions**: Comment complex logic

## Related Concepts

- **[Policy Conjunction](/concepts/policy-conjunction)**: How policies from different phases combine
- **[Policy Libraries](/concepts/policy-libraries)**: Reusable Rego code for policies
- **[PORC](/concepts/porc)**: The input format for policy evaluation
- **[Operations](/concepts/operations)**: Route requests to operation phase policies
- **[Roles](/concepts/roles)**: Connect principals to identity phase policies
- **[Resource Groups](/concepts/resource-groups)**: Connect resources to resource phase policies
- **[Scopes](/concepts/scopes)**: Connect access methods to scope phase policies
- **[Policy Domains](/concepts/policy-domains)**: Container for policy definitions