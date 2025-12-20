---
sidebar_position: 3
---

# Manetu Resource Notation (MRN)

**Manetu Resource Notation (MRN)** is a universal identifier scheme used throughout the PolicyEngine to uniquely identify entities. Despite "Resource" in the name, MRNs identify all entity types: policies, roles, groups, resource groups, scopes, and resources.

## Overview

MRNs provide:

- **Universal identification**: A single format for all entity types
- **Namespacing**: Prevent collisions across organizations and systems
- **Self-describing structure**: The MRN format reveals what type of entity it identifies
- **Pattern matching**: Regular expressions can match MRN patterns for routing and filtering

## MRN Format

```
mrn:<type>:<namespace>:<class>:<instance>
```

| Component | Description | Example |
|-----------|-------------|---------|
| `mrn:` | Fixed prefix | Always `mrn:` |
| `type` | Entity type or system | `iam`, `vault`, `data`, `app` |
| `namespace` | Organization or domain | `acme.com`, `manetu.io` |
| `class` | Entity classification | `role`, `policy`, `secret`, `user` |
| `instance` | Unique instance identifier | `admin`, `api-key`, `12345` |

:::tip MRN Scheme
The PolicyEngine does not enforce any specific scheme, including the 'mrn:' prefix. The scheme above is only a suggestion, and any scheme will work as long as you minimally maintain id-uniqueness.  However, you are encouraged to adopt a naming convention that provides context to the observer, such as the type of resource, and suggest that you use the methodology outlined here.
:::

## MRN Examples by Entity Type

### Policies

```
mrn:iam:acme.com:policy:allow-all
mrn:iam:acme.com:policy:authenticated-only
mrn:iam:acme.com:policy:clearance-required
```

### Roles

```
mrn:iam:acme.com:role:admin
mrn:iam:acme.com:role:editor
mrn:iam:acme.com:role:viewer
```

### Groups

```
mrn:iam:acme.com:group:engineering
mrn:iam:acme.com:group:finance
mrn:iam:acme.com:group:executives
```

### Resource Groups

```
mrn:iam:acme.com:resource-group:public
mrn:iam:acme.com:resource-group:internal
mrn:iam:acme.com:resource-group:sensitive
```

### Scopes

```
mrn:iam:acme.com:scope:read-only
mrn:iam:acme.com:scope:full-access
mrn:iam:acme.com:scope:admin
```

### Resources

```
mrn:vault:acme.com:secret:api-key
mrn:data:acme.com:document:quarterly-report
mrn:app:acme.com:user:12345
```

## MRN Usage in PolicyDomains

MRNs connect entities throughout the PolicyDomain schema:

```yaml
apiVersion: manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: example
spec:
  policies:
    - mrn: "mrn:iam:policy:editor-access"       # Policy MRN
      name: editor-access
      rego: |
        package authz
        default allow = false
        allow { input.operation.method in ["read", "write"] }

  roles:
    - mrn: "mrn:iam:role:editor"                # Role MRN
      name: editor
      policy: "mrn:iam:policy:editor-access"    # References policy MRN

  groups:
    - mrn: "mrn:iam:group:content-team"         # Group MRN
      name: content-team
      roles:
        - "mrn:iam:role:editor"                 # References role MRN

  resource-groups:
    - mrn: "mrn:iam:resource-group:documents"   # Resource group MRN
      name: documents
      policy: "mrn:iam:policy:editor-access"    # References policy MRN
```

## MRN Patterns and Matching

MRNs are designed to work with regular expressions for routing and filtering.

### In Operations

Route requests to policies based on MRN-like operation patterns:

```yaml
operations:
  - name: vault-read
    selector:
      - "vault:.*:read"      # Match vault read operations
    policy: "mrn:iam:policy:vault-readonly"
```

### In Resource Routing

Match resource MRNs to assign them to groups:

```yaml
resources:
  - name: sensitive-data
    selector:
      - "mrn:data:sensitive:.*"    # Match sensitive data MRNs
      - "mrn:secret:.*"            # Match all secrets
    group: "mrn:iam:resource-group:sensitive"
```

### In Policies

Use MRN patterns in Rego for fine-grained control:

```rego
package authz

default allow = false

# Allow if principal has any admin role (MRN pattern)
allow {
    some role in input.principal.mroles
    startswith(role, "mrn:iam:role:admin")
}

# Allow access to specific resource types
allow {
    startswith(input.resource.id, "mrn:data:public:")
}
```

## MRN in PORC Expressions

MRNs appear throughout [PORC expressions](/concepts/porc):

```json
{
  "principal": {
    "sub": "user@acme.com",
    "mroles": [
      "mrn:iam:role:editor",
      "mrn:iam:role:viewer"
    ],
    "mgroups": [
      "mrn:iam:group:content-team"
    ],
    "scopes": [
      "mrn:iam:scope:full-access"
    ]
  },
  "operation": "documents:write",
  "resource": {
    "id": "mrn:data:acme.com:document:draft-123",
    "group": "mrn:iam:resource-group:documents",
    "owner": "author@acme.com"
  },
  "context": {}
}
```

## MRN Namespacing Strategies

### By Organization

Use domain names for multi-tenant systems:

```
mrn:iam:acme.com:role:admin
mrn:iam:globex.io:role:admin
mrn:iam:initech.com:role:admin
```

### By Environment

Include environment in the namespace:

```
mrn:iam:prod.acme.com:role:admin
mrn:iam:staging.acme.com:role:admin
mrn:iam:dev.acme.com:role:admin
```

### By Service

Namespace by service or subsystem:

```
mrn:billing:acme.com:role:invoicer
mrn:inventory:acme.com:role:manager
mrn:shipping:acme.com:role:dispatcher
```

## Best Practices

### 1. Use Consistent Namespacing

Establish a naming convention and stick to it:

```yaml
# Good: Consistent namespace format
mrn:iam:acme.com:role:admin
mrn:iam:acme.com:policy:admin-access
mrn:iam:acme.com:group:administrators

# Avoid: Inconsistent namespacing
mrn:iam:acme:role:admin
mrn:iam:ACME.COM:policy:admin-access
mrn:iam:acme.com:group:admins
```

### 2. Use Descriptive Instance Names

Make instance identifiers meaningful:

```yaml
# Good: Descriptive names
mrn:iam:acme.com:role:billing-admin
mrn:iam:acme.com:policy:pii-access-clearance

# Avoid: Cryptic names
mrn:iam:acme.com:role:r1
mrn:iam:acme.com:policy:pol-7b
```

### 3. Keep MRNs Immutable

Once assigned, MRNs should not change. They may be referenced by:
- Other entities in the PolicyDomain
- External systems and tokens
- Audit logs and compliance records

### 4. Plan for Hierarchy

Structure MRNs to support future pattern matching:

```yaml
# Good: Hierarchical structure enables pattern matching
mrn:iam:acme.com:role:finance-admin
mrn:iam:acme.com:role:finance-viewer
mrn:iam:acme.com:role:finance-auditor
# Can match: "mrn:iam:acme.com:role:finance-.*"

# Less flexible: Flat structure
mrn:iam:acme.com:role:admin-finance
mrn:iam:acme.com:role:viewer-finance
```

### 5. Document Your MRN Schema

Maintain a registry of MRN patterns used in your organization to prevent collisions and ensure consistency.

## Related Concepts

- **[Policies](/concepts/policies)**: Identified by MRNs, referenced by roles and resource groups
- **[Roles](/concepts/roles)**: Identified by MRNs, assigned to principals
- **[Groups](/concepts/groups)**: Identified by MRNs, bundle roles together
- **[Resource Groups](/concepts/resource-groups)**: Identified by MRNs, associate resources with policies
- **[Resources](/concepts/resources)**: Identified by MRNs, the entities being protected
- **[Scopes](/concepts/scopes)**: Identified by MRNs, constrain access methods
