---
sidebar_position: 2
---

# Creating Your First PolicyDomain

This guide walks through creating a complete [PolicyDomain](/concepts/policy-domains) from scratch, starting with the essentials and building up gradually.

## PolicyDomain Structure

A PolicyDomain YAML file has this structure:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: domain-name
spec:
  policies: []          # Access control policies
  roles: []             # Role-to-policy mappings
  groups: []            # Group-to-role mappings
  resource-groups: []   # Resource-to-policy mappings
  operations: []        # Operation routing
  resources: []         # Resource selector routing (v1alpha4+)
  scopes: []            # Access-method constraint policies
  mappers: []           # Input transformation (optional)
  policy-libraries: []  # Reusable Rego code (optional)
```

For a detailed explanation of each component, see the [Concepts](/concepts) section.

## Step 1: Define [Policies](/concepts/policies)

Policies contain Rego code that makes access control decisions. Most policies define an `allow` rule that returns `true` (grant) or `false` (deny).

Let's start with three policies:

```yaml
spec:
  policies:
    # Full access policy
    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Grants full access"
      rego: |
        package authz
        default allow = true

    # Read-only policy
    - mrn: &read-only "mrn:iam:policy:read-only"
      name: read-only
      description: "Read-only access - allows get, read, and list operations"
      rego: |
        package authz
        import rego.v1

        default allow = false

        # Allow read-only operations
        allow if {
            ro_patterns := {"*:get", "*:read", "*:list"}
            some pattern in ro_patterns
            glob.match(pattern, [], input.operation)
        }

    # Operation phase policy (see note below about tri-state)
    - mrn: &operation-default "mrn:iam:policy:operation-default"
      name: operation-default
      description: "Default operation policy - defers to identity and resource phases"
      rego: |
        package authz
        # Operation policies use tri-state: negative=deny, 0=continue, positive=grant override
        # Returning 0 defers the decision to identity and resource phases
        default allow = 0
```

:::info[Operation Policies Are Different]
Operation policies use a [tri-state](/concepts/policy-conjunction#operation-phase-tri-level-policies) return value instead of simple true/false:
- **Negative** (e.g., `-1`): Deny immediately
- **Zero** (`0`): Continue to identity and resource phases
- **Positive** (e.g., `1`): Grant immediately, skip other phases

Using `default allow = 0` keeps this example simple by deferring all decisions to the identity and resource phases. In practice, operation policies often perform checks like verifying authentication (e.g., `input.principal != {}`). See [Policy Conjunction](/concepts/policy-conjunction) for real-world patterns.
:::

:::tip[YAML Anchors]
[YAML anchors](https://en.wikipedia.org/wiki/YAML#Advanced_components), such as `&allow-all`, can be referenced later with `*allow-all`. This keeps your PolicyDomain DRY and ensures consistent MRN references.
:::

## Step 2: Define [Roles](/concepts/roles)

Roles map to policies and are assigned to principals (users). When a user has a role, their access is evaluated against that role's policy.

```yaml
  roles:
    - mrn: &admin-role "mrn:iam:role:admin"
      name: admin
      description: "Administrator with full access"
      policy: *allow-all  # references the &allow-all anchor from Step 1

    - mrn: &viewer-role "mrn:iam:role:viewer"
      name: viewer
      description: "Read-only access"
      policy: *read-only
```

## Step 3: Define [Groups](/concepts/groups)

Groups organize roles together. Principals can be members of groups, inheriting all roles assigned to that group.

```yaml
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      description: "Administrator group"
      roles:
        - *admin-role

    - mrn: "mrn:iam:group:readers"
      name: readers
      description: "Read-only users"
      roles:
        - *viewer-role
```

## Step 4: Define [Resource Groups](/concepts/resource-groups)

Resource groups associate policies with sets of resources. Every resource belongs to a resource group, and that group's policy is evaluated during authorization.

```yaml
  resource-groups:
    - mrn: &default-resources "mrn:iam:resource-group:default"
      name: default
      description: "Default resource group"
      default: true
      policy: *allow-all

    - mrn: "mrn:iam:resource-group:sensitive"
      name: sensitive
      description: "Sensitive resources requiring stricter access"
      policy: *sensitive-data
```

The `default: true` flag designates `mrn:iam:resource-group:default` as the fallback group for resources that don't match any specific routing rules.

## Step 5: Define [Operations](/concepts/operations)

Operations route incoming requests to policies based on the operation string. Selectors use regular expressions to match operations.

```yaml
  operations:
    - name: all-operations
      selector:
        - ".*"  # Match all operations
      policy: *operation-default
```

This example routes all operations through the tri-level `operation-default` policy. See [Operations](/concepts/operations) for examples of more complex operation routing patterns.

## Step 6: Define [Mappers](/concepts/mappers) (Optional)

Mappers are only needed when integrating with systems that cannot construct [PORC expressions](/concepts/porc) directly, such as Envoy's ext_authz protocol. Most applications should build PORC expressions in their own code instead.

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
            "resource": sprintf("mrn:api:%s", [path]),
            "context": input
        }
```

:::tip[Resource Format]
This uses the simple MRN string format, which is the recommended approach. See [Resource Resolution](/integration/resource-resolution) for details on how the PolicyEngine enriches resources with metadata.
:::

## Complete Minimal Example

Here's a complete, minimal PolicyDomain that you can use as a starting point:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: my-first-domain
spec:
  policies:
    - mrn: &operation-default "mrn:iam:policy:operation-default"
      name: operation-default
      description: "Defers to identity and resource phases"
      rego: |
        package authz
        default allow = 0  # operation policies use tri-state integers

    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Grants full access"
      rego: |
        package authz
        default allow = true

    - mrn: &read-only "mrn:iam:policy:read-only"
      name: read-only
      description: "Read-only access"
      rego: |
        package authz
        import rego.v1

        default allow = false

        allow if {
            ro_patterns := {"*:get", "*:read", "*:list"}
            some pattern in ro_patterns
            glob.match(pattern, [], input.operation)
        }

  roles:
    - mrn: &admin-role "mrn:iam:role:admin"
      name: admin
      policy: *allow-all

    - mrn: &viewer-role "mrn:iam:role:viewer"
      name: viewer
      policy: *read-only

  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      roles:
        - *admin-role

  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      default: true
      policy: *allow-all

  operations:
    - name: all-operations
      selector:
        - ".*"
      policy: *operation-default
```

For a more comprehensive example, see `cmd/mpe/test/example-domain.yml` in the repository.

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

## Advanced Topics

Once you're comfortable with the basics, explore these advanced features:

- **[Policy Libraries](/concepts/policy-libraries)** — Extract reusable Rego code into shared libraries that multiple policies can import
- **[Policy Conjunction](/concepts/policy-conjunction)** — Understand how the evaluation phases work together, including tri-state return values for early grant/deny decisions
- **[Resource Routing](/concepts/resources#resource-routing-v1alpha4)** — Route resources to groups based on MRN patterns
- **[Scopes](/concepts/scopes)** — Add access-method constraints for scenarios like API keys vs. interactive sessions

## Next Steps

- [Testing Policies](/quick-start/testing-policies) - Test your PolicyDomain
- [PolicyDomain Schema Reference](/reference/schema) - Complete schema documentation
