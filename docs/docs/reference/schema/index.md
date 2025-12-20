---
sidebar_position: 1
---

# PolicyDomain Schema

Complete reference for the PolicyDomain YAML schema.

## Overview

A PolicyDomain is defined in YAML with the following top-level structure:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: string
spec:
  policy-libraries: []
  policies: []
  roles: []
  groups: []
  resource-groups: []
  resources: []       # New in v1alpha4
  scopes: []
  operations: []
  mappers: []
```

## API Version

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
```

Supported versions: `v1alpha3`, `v1alpha4`

### Version Differences

| Feature | v1alpha3 | v1alpha4 |
|---------|----------|----------|
| `resources` section | Not available | Available |
| `selector` in operations | Optional | Required |
| `selector` in mappers | Optional | Required |

## Kind

The PolicyEngine supports two related document kinds:

| Kind | Description |
|------|-------------|
| `PolicyDomain` | Complete bundle with inline Rego code |
| `PolicyDomainReference` | Development format that references external `.rego` files |

### PolicyDomain vs PolicyDomainReference

**PolicyDomainReference** is a superset of **PolicyDomain** designed for development workflows. The key differences:

| Aspect | PolicyDomain | PolicyDomainReference |
|--------|--------------|----------------------|
| **Rego code** | Inline `rego` field only | Either `rego` (inline) or `rego_filename` (external file) |
| **Use case** | Deployment, runtime | Development, source control |
| **Kubernetes Operator** | Supported (Premium) | Must convert first |

**Which format should I use?**

- **For development**: Use `PolicyDomainReference` with `rego_filename` to keep Rego code in separate `.rego` files. This enables IDE syntax highlighting, easier testing, and cleaner diffs in version control.

- **For deployment**: Use `PolicyDomain` with inline `rego`. Convert from `PolicyDomainReference` using [`mpe build`](/reference/cli/build).

- **OSS users**: All tooling (`mpe test`, `mpe serve`, Go API) accepts both formats. Choose based on your workflow preference.

- **Premium users**: The Kubernetes Operator requires `PolicyDomain` format. Develop in either format, but run `mpe build` before deployment.

### Converting Between Formats

Use `mpe build` to convert `PolicyDomainReference` to `PolicyDomain`:

```bash
# Convert reference format to deployment format
mpe build -f policy-domain-ref.yaml -o policy-domain.yaml
```

The build process:
1. Reads each `rego_filename` reference
2. Loads the external `.rego` file content
3. Replaces `rego_filename` with inline `rego`
4. Changes `kind` from `PolicyDomainReference` to `PolicyDomain`

See [`mpe build`](/reference/cli/build) for details.

## Metadata

```yaml
metadata:
  name: my-domain-name
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for the domain |

## Spec Sections

| Section | Description |
|---------|-------------|
| [policy-libraries](/reference/schema/policy-libraries) | Reusable Rego code |
| [policies](/reference/schema/policies) | Access control policies |
| [roles](/reference/schema/roles) | Identity-to-policy mappings |
| [groups](/reference/schema/groups) | Group-to-role mappings |
| [resource-groups](/reference/schema/resource-groups) | Resource-to-policy mappings |
| [resources](/reference/schema/resources) | Resource selector-based routing (v1alpha4+) |
| [scopes](/reference/schema/scopes) | Access-method constraint policies |
| [operations](/reference/schema/operations) | Operation routing |
| [mappers](/reference/schema/mappers) | Input transformation |

## Common Fields

### MRN (Manetu Resource Notation)

All entities use MRN for identification:

```
mrn:<type>:<namespace>:<class>:<instance>
```

Examples:
- `mrn:iam:policy:admin`
- `mrn:iam:role:developer`
- `mrn:app:myservice:resource-group:default`

### YAML Anchors

Use YAML anchors for reference:

```yaml
policies:
  - mrn: &my-policy "mrn:iam:policy:my-policy"
    name: my-policy
    rego: |
      package authz
      default allow = true

roles:
  - mrn: "mrn:iam:role:admin"
    name: admin
    policy: *my-policy  # Reference
```

## Full Example

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: example-domain
spec:
  policy-libraries:
    - mrn: &utils "mrn:iam:library:utils"
      name: utils
      rego: |
        package utils
        match_any(patterns, value) {
            glob.match(patterns[_], [], value)
        }

  policies:
    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = true

    - mrn: &read-only "mrn:iam:policy:read-only"
      name: read-only
      rego: |
        package authz
        default allow = false
        allow { input.operation == "read" }

    - mrn: &main "mrn:iam:policy:main"
      name: main
      dependencies:
        - *utils
      rego: |
        package authz
        import data.utils
        default allow = 0  # Tri-level: negative=DENY, 0=GRANT, positive=GRANT Override
        allow = -1 { input.principal == {} }  # DENY

  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      policy: *allow-all

  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      roles:
        - "mrn:iam:role:admin"

  resource-groups:
    - mrn: &rg-default "mrn:iam:resource-group:default"
      name: default
      default: true
      policy: *allow-all

    - mrn: &rg-sensitive "mrn:iam:resource-group:sensitive"
      name: sensitive
      policy: *read-only

  # New in v1alpha4: Resources map MRNs to resource groups via selectors
  resources:
    - name: sensitive-data
      description: "Sensitive data requiring read-only access"
      selector:
        - "mrn:data:sensitive:.*"
        - "mrn:secret:.*"
      group: *rg-sensitive
      annotations:
        - name: classification
          value: "\"HIGH\""

  scopes:
    - mrn: "mrn:iam:scope:api"
      name: api
      policy: *allow-all

  operations:
    - name: api
      selector:
        - ".*"
      policy: *main

  mappers:
    - name: http
      selector:
        - ".*"
      rego: |
        package mapper
        porc := {
            "principal": input.claims,
            "operation": input.operation,
            "resource": input.resource,
            "context": input
        }
```
