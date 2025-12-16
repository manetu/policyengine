---
sidebar_position: 2
---

# Creating Your First PolicyDomain

This guide walks through creating a complete [PolicyDomain](/concepts/policy-domains) from scratch.

## PolicyDomain Structure

A PolicyDomain YAML file has this structure:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: domain-name
spec:
  policy-libraries: []  # Reusable Rego code
  policies: []          # Access control policies
  roles: []             # Role-to-policy mappings
  groups: []            # Group-to-role mappings
  resource-groups: []   # Resource-to-policy mappings
  resources: []         # Resource selector routing (v1alpha4+)
  scopes: []            # Access-method constraint policies
  operations: []        # Operation routing
  mappers: []           # Input transformation
```

For a detailed explanation of each component, see the [Concepts](/concepts) section.

## Step 1: Define [Policy Libraries](/concepts/policy-libraries)

Policy libraries contain reusable Rego code. Create helper functions that multiple policies can use:

```yaml
spec:
  policy-libraries:
    - mrn: &utils "mrn:iam:library:utils"
      name: utils
      description: "Common utility functions"
      rego: |
        package utils

        # Glob pattern matching helper
        match_any(patterns, value) {
            glob.match(patterns[_], [], value)
        }

        # Read-only operation patterns
        ro_operations := {
            "*:get",
            "*:read",
            "*:list",
        }
```

## Step 2: Define [Policies](/concepts/policies)

Policies contain the Rego code that makes access control decisions:

```yaml
  policies:
    # Operation phase policy (Phase 1) - uses tri-level output
    - mrn: &main-policy "mrn:iam:policy:main"
      name: main
      description: "Operation phase policy - handles public endpoints and JWT validation"
      rego: |
        package authz

        # Tri-level return codes (operation phase only):
        #  Negative (e.g., -1): Deny (same as any phase denying)
        #  Zero (0): Grant (same as any phase); other phases still evaluated
        #  Positive (e.g., 1): GRANT Override - skip all other phases
        default allow = 0

        # Deny unauthenticated requests on protected endpoints
        allow = -1 {
            input.principal == {}
            not is_public_operation
        }

        # GRANT Override for public operations (bypasses identity phase)
        allow = 1 {
            is_public_operation
        }

        is_public_operation {
            input.operation in {"public:health:check"}
        }

    # Full access policy
    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Grants full access"
      rego: |
        package authz
        default allow = true

    # Read-only policy using library
    - mrn: &read-only "mrn:iam:policy:read-only"
      name: read-only
      description: "Read-only access"
      dependencies:
        - *utils
      rego: |
        package authz
        import data.utils

        default allow = false

        allow {
            utils.match_any(utils.ro_operations, input.operation)
        }
```

## Step 3: Define [Roles](/concepts/roles)

Roles assign policies to identity-based access:

```yaml
  roles:
    - mrn: &admin-role "mrn:iam:role:admin"
      name: admin
      description: "Administrator with full access"
      policy: *allow-all

    - mrn: &viewer-role "mrn:iam:role:viewer"
      name: viewer
      description: "Read-only access"
      policy: *read-only
```

## Step 4: Define [Groups](/concepts/groups)

Groups organize roles:

```yaml
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      description: "Administrator group"
      roles:
        - *admin-role
```

## Step 5: Define [Resource Groups](/concepts/resource-groups)

Resource groups apply policies to resources:

```yaml
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      description: "Default resource group"
      default: true
      policy: *allow-all
```

## Step 6: Define [Operations](/concepts/operations)

Operations route requests to policies:

```yaml
  operations:
    - name: api
      selector:
        - ".*"  # Match all operations
      policy: *main-policy
```

## Step 7: Define [Mappers](/concepts/mappers) (Optional)

Mappers transform external inputs (like Envoy) into [PORC](/concepts/porc) expressions:

```yaml
  mappers:
    - name: http-mapper
      selector:
        - ".*"
      rego: |
        package mapper
        import rego.v1

        default claims := {}

        method := lower(input.request.http.method)
        path := input.request.http.path

        # Extract JWT claims
        auth := input.request.http.headers.authorization
        token := split(auth, "Bearer ")[1]
        claims := io.jwt.decode(token)[1]

        porc := {
            "principal": claims,
            "operation": sprintf("api:http:%s", [method]),
            "resource": {
                "id": path,
                "group": "mrn:iam:resource-group:default"
            },
            "context": input
        }
```

## Complete Example

See the complete example in the repository at `cmd/mpe/test/example-domain.yml`.

## Using External Rego Files

For better maintainability, you can use `PolicyDomainReference` with external `.rego` files:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomainReference
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:main"
      name: main
      rego_filename: policies/main.rego  # External file
```

Then build:

```bash
mpe build -f my-domain-ref.yml
```

This creates a `PolicyDomain` with the Rego content inlined.

## Next Steps

- [Testing Policies](/quick-start/testing-policies) - Test your PolicyDomain
- [PolicyDomain Schema Reference](/reference/schema) - Complete schema documentation
