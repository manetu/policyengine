---
sidebar_position: 7
---

# Resources

**Resources** are accessible entities within your application. Each resource has a unique identifier and metadata that policies can use for access control decisions.

## Overview

Resources in the PolicyEngine are characterized by:

- **Unique identifier** (MRN)
- **Ownership**: Who owns the resource
- **Classification**: Security level
- **Annotations**: Custom metadata
- **Resource Group**: Policy association

## Resource Identifiers

Resources are identified using **[Manetu Resource Notation (MRN)](/concepts/mrn)**, a universal identifier scheme used throughout the PolicyEngine:

```
mrn:<type>:<namespace>:<class>:<instance>
```

Example resource MRNs:

| MRN | Description |
|-----|-------------|
| `mrn:vault:acme.com:secret:api-key` | A secret in the vault |
| `mrn:data:acme.com:document:report-q4` | A document |
| `mrn:app:myservice:user:12345` | A user in an application |

See the [MRN documentation](/concepts/mrn) for complete details on the MRN format and usage patterns.

## Resource Metadata

### Ownership

Every resource has an **owner** - an MRN reference to an identity:

```json
{
  "resource": {
    "id": "mrn:app:data:document:123",
    "owner": "user@example.com"
  }
}
```

Use ownership in policies:

```rego
package authz

default allow = false

# Owner has full access
allow {
    input.principal.sub == input.resource.owner
}
```

### Classification

**Classification** is a security rating:

| Level | Value | Description |
|-------|-------|-------------|
| `LOW` | 1 | Public data |
| `MODERATE` | 2 | Internal data |
| `HIGH` | 3 | Confidential data |
| `MAXIMUM` | 4 | Top secret data |
| `UNASSIGNED` | 5 | Not yet classified |

Use classification with clearance:

```rego
package authz

default allow = false

ratings := {"LOW": 1, "MODERATE": 2, "HIGH": 3, "MAXIMUM": 4}

# Grant if clearance >= classification
allow {
    ratings[input.principal.mclearance] >= ratings[input.resource.classification]
}
```

### Resource Group

Every resource belongs to a **Resource Group** that determines which policies apply:

```json
{
  "resource": {
    "id": "mrn:app:data:item:456",
    "group": "mrn:iam:resource-group:sensitive-data"
  }
}
```

## Resource Groups

Resource groups associate policies with sets of resources:

```yaml
spec:
  resource-groups:
    - mrn: "mrn:iam:resource-group:public"
      name: public
      description: "Publicly accessible resources"
      policy: "mrn:iam:policy:allow-all"

    - mrn: "mrn:iam:resource-group:internal"
      name: internal
      description: "Internal resources requiring authentication"
      default: true  # Default group for new resources
      policy: "mrn:iam:policy:authenticated-only"

    - mrn: "mrn:iam:resource-group:sensitive"
      name: sensitive
      description: "Sensitive resources with strict access"
      policy: "mrn:iam:policy:clearance-required"
```

## Resource Routing (v1alpha4+)

Starting with v1alpha4, you can use the `resources` section to route resources to groups based on MRN patterns:

```yaml
spec:
  resources:
    - name: sensitive-data
      description: "Route sensitive data to restricted group"
      selector:
        - "mrn:data:sensitive:.*"
        - "mrn:secret:.*"
      group: "mrn:iam:resource-group:sensitive"
      annotations:
        - name: classification
          value: "\"HIGH\""
```

When a resource MRN is resolved:
1. The system checks if any `resources` selector matches the MRN
2. If a match is found, the resource is assigned to the corresponding group
3. If no match is found, the resource falls back to the default resource group

See the [Resources Schema Reference](/reference/schema/resources) for detailed documentation.

## Annotations

**Annotations** are custom key-value pairs:

```json
{
  "resource": {
    "id": "mrn:app:data:report:monthly",
    "annotations": {
      "department": "finance",
      "retention": "7years",
      "pii": true
    }
  }
}
```

Use annotations in policies:

```rego
package authz

default allow = false

# Only finance department can access finance resources
allow {
    input.resource.annotations.department == "finance"
    input.principal.mannotations.department == "finance"
}

# PII data requires special handling
allow {
    not input.resource.annotations.pii
}

allow {
    input.resource.annotations.pii
    input.principal.mroles[_] == "mrn:iam:role:pii-handler"
}
```

## Resource in PORC

Resources appear in the PORC expression:

```json
{
  "principal": { ... },
  "operation": "vault:secret:read",
  "resource": {
    "id": "mrn:vault:acme:secret:api-key",
    "owner": "admin@acme.com",
    "group": "mrn:iam:resource-group:secrets",
    "classification": "HIGH",
    "annotations": {
      "environment": "production",
      "expires": "2024-12-31"
    }
  },
  "context": { ... }
}
```

## Best Practices

1. **Use meaningful MRNs**: Make resource IDs descriptive
2. **Set ownership**: Always assign an owner
3. **Classify appropriately**: Use classification to protect sensitive data
4. **Use resource groups**: Organize resources by access patterns
5. **Leverage annotation inheritance**: Define default annotations on resource groups and override on specific resources as needed. In the hierarchy (Resource Group → Resource), resource-level annotations take precedence over resource group annotations.
6. **Keep annotations lightweight**: Don't store large data in annotations

## Related Concepts

- **[MRN](/concepts/mrn)**: The universal identifier format for resources and all other entities
- **[Resource Groups](/concepts/resource-groups)**: How resources are associated with policies
- **[Annotations](/concepts/annotations)**: Metadata inheritance (resource annotations override resource group annotations)
- **[Operations](/concepts/operations)**: Actions performed on resources
- **[Policy Conjunction](/concepts/policy-conjunction)**: How resource policies fit into Phase 3 evaluation
