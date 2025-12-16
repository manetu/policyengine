---
sidebar_position: 11
---

# Policy Libraries

**Policy Libraries** contain reusable Rego code that can be shared across multiple policies within a PolicyDomain.

## Overview

Libraries help you:

- **Reduce duplication**: Write helper functions once
- **Improve maintainability**: Update logic in one place
- **Organize code**: Separate concerns into focused packages

:::warning[Package Name Requirements]
Policy Libraries have specific package naming requirements:

1. **Must NOT use `package authz`** — The `authz` package is reserved for authorization policies (those defined in the `policies` section that make access decisions). Libraries use their own unique package names (e.g., `package helpers`, `package utils`).

2. **Must be unique across all dependencies** — When an authorization policy imports multiple libraries, each library must have a distinct package name. If two libraries both declare `package utils`, a collision will occur.

**Best practice:** Use descriptive, organization-specific package names to avoid collisions (e.g., `package myorg.helpers` or `package acme.validation`). This ensures libraries can be safely combined in any policy.
:::

## Defining a Library

```yaml
spec:
  policy-libraries:
    - mrn: "mrn:iam:library:helpers"
      name: helpers
      description: "Common helper functions"
      rego: |
        package helpers

        # Glob pattern matching
        match_any(patterns, value) {
            glob.match(patterns[_], [], value)
        }

        # Check if principal has a specific role
        has_role(role) {
            input.principal.mroles[_] == role
        }

        # Check if principal is in a group
        in_group(group) {
            input.principal.mgroups[_] == group
        }
```

## Using Libraries in Policies

Declare the library as a dependency and import it:

```yaml
spec:
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
            helpers.has_role("mrn:iam:role:admin")
        }
```

## Library Dependencies

Libraries can depend on other libraries:

```yaml
spec:
  policy-libraries:
    - mrn: &utils "mrn:iam:library:utils"
      name: utils
      rego: |
        package utils

        ro_operations := {"*:read", "*:list", "*:get"}

    - mrn: "mrn:iam:library:access"
      name: access
      dependencies:
        - *utils
      rego: |
        package access
        import data.utils

        is_readonly {
            glob.match(utils.ro_operations[_], [], input.operation)
        }
```

## Common Library Patterns

### Operation Helpers

```rego
package operations

# Read-only operations
ro_operations := {
    "*:read",
    "*:list",
    "*:get",
    "*:head"
}

# Write operations
write_operations := {
    "*:create",
    "*:update",
    "*:write",
    "*:delete"
}

is_read_only {
    glob.match(ro_operations[_], [], input.operation)
}

is_write {
    glob.match(write_operations[_], [], input.operation)
}
```

### Role Helpers

```rego
package roles

admin_roles := {
    "mrn:iam:role:admin",
    "mrn:iam:role:superadmin"
}

is_admin {
    input.principal.mroles[_] in admin_roles
}

has_any_role(required_roles) {
    some role in input.principal.mroles
    role in required_roles
}
```

### Resource Helpers

```rego
package resources

is_owner {
    input.principal.sub == input.resource.owner
}

clearance_levels := {
    "LOW": 1,
    "MODERATE": 2,
    "HIGH": 3,
    "MAXIMUM": 4,
    "UNASSIGNED": 5
}

has_clearance {
    clearance_levels[input.principal.mclearance] >= clearance_levels[input.resource.classification]
}
```

### Validation Helpers

```rego
package validation

# Check if principal is authenticated
is_authenticated {
    input.principal != {}
    input.principal.sub != ""
}

# Check if principal has a valid JWT
has_valid_jwt {
    input.principal.exp > time.now_ns() / 1000000000
}
```

## Cross-Domain References

Reference libraries from other PolicyDomains:

```yaml
spec:
  policies:
    - mrn: "mrn:iam:policy:my-policy"
      name: my-policy
      dependencies:
        - "other-domain/common-utils"  # Cross-domain reference
      rego: |
        package authz
        import data.common_utils
        # Note: package name uses underscores

        default allow = false

        allow {
            common_utils.is_valid(input)
        }
```

## Best Practices

1. **Single responsibility**: Each library should have a focused purpose
2. **Clear naming**: Use descriptive package and function names
3. **Document functions**: Add comments explaining what functions do
4. **Avoid side effects**: Libraries should be pure functions
5. **Test libraries**: Write tests for library functions separately
