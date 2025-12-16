---
sidebar_position: 12
---

# Annotations

**Annotations** are key-value pairs that can be attached to various entities for custom metadata and policy decisions. They support inheritance hierarchies that allow general definitions to be overridden by more specific ones.

## Overview

Annotations provide flexible metadata that:

- Can be attached to roles, groups, scopes, resource groups, resources, and principals
- Are accessible during policy evaluation via the PORC
- Support any valid JSON values
- Follow inheritance hierarchies where more specific definitions take precedence

## Where Annotations Apply

Annotations can be defined on multiple entity types:

| Entity | Defined In                                                                                  | Description |
|--------|---------------------------------------------------------------------------------------------|-------------|
| Role | PolicyDomain `spec.roles[].annotations`                                                     | Role-specific metadata |
| Group | PolicyDomain `spec.groups[].annotations`                                                    | Group-specific metadata |
| Scope | PolicyDomain `spec.scopes[].annotations`                                                    | Scope-specific metadata |
| Resource Group | PolicyDomain `spec.resource-groups[].annotations`                                           | Resource group metadata |
| Resource | PolicyDomain `spec.resources[].annotations`, or external resource resolution <FeatureChip variant="premium" label="Premium Only" />
| Resource-specific metadata |
| Principal | JWT claims                                                                                  | Identity-level metadata |

## Annotation Inheritance

Annotations follow inheritance hierarchies where conflicts are resolved by precedence rules. More specific or contextual definitions override more general ones.

### Identity Annotation Hierarchy

For identity-related annotations (available in `input.principal.mannotations`), the inheritance order from **least to most dominant** is:

```
Roles → Groups → Scopes → Principal Claims
```

| Precedence | Source | Description |
|------------|--------|-------------|
| 1 (lowest) | Roles | Annotations defined on roles |
| 2 | Groups | Annotations defined on groups |
| 3 | Scopes | Annotations defined on scopes |
| 4 (highest) | Principal | Annotations in JWT claims (`mannotations`) |

**Example**: If the same annotation key `department` is defined on both a Role and a Group that apply to a request, the Group's value takes precedence. If also defined in the principal's JWT claims, that value wins.

```yaml
# Role definition
roles:
  - mrn: "mrn:iam:role:developer"
    annotations:
      department: "engineering"    # Precedence 1
      access_level: "standard"

# Group definition
groups:
  - mrn: "mrn:iam:group:platform-team"
    annotations:
      department: "platform"       # Precedence 2 - overrides role
      team: "infrastructure"

# Scope definition (if applicable)
scopes:
  - mrn: "mrn:iam:scope:elevated"
    annotations:
      access_level: "elevated"     # Precedence 3 - overrides role

# Principal JWT claims
principal:
  mannotations:
    department: "security"         # Precedence 4 - overrides all others
```

**Resulting `input.principal.mannotations`**:
```json
{
  "department": "security",      // From principal (highest precedence)
  "access_level": "elevated",    // From scope
  "team": "infrastructure"       // From group (no conflict)
}
```

### Resource Annotation Hierarchy

For resource-related annotations (available in `input.resource.annotations`), the inheritance order from **least to most dominant** is:

```
Resource Group → Resource
```

| Precedence | Source | Description |
|------------|--------|-------------|
| 1 (lowest) | Resource Group | Annotations defined on the resource group |
| 2 (highest) | Resource | Annotations on the specific resource |

**Example**: If a resource belongs to a resource group, annotations from the resource group are inherited, but any annotations defined directly on the resource take precedence.

```yaml
# Resource Group definition
resource-groups:
  - mrn: "mrn:iam:resource-group:customer-data"
    annotations:
      data_classification: "confidential"
      retention_days: "365"
      requires_audit: "true"

# Resource with override
resource:
  mrn: "mrn:data:customer:12345"
  annotations:
    retention_days: "730"          # Overrides resource group
    special_handling: "true"       # Additional annotation
```

**Resulting `input.resource.annotations`**:
```json
{
  "data_classification": "confidential",  // From resource group
  "retention_days": "730",                // From resource (overrides)
  "requires_audit": "true",               // From resource group
  "special_handling": "true"              // From resource (new)
}
```

### Inheritance Use Cases

#### Establishing Defaults with Overrides

Define baseline annotations at a general level and override for specific cases:

```yaml
# All developers get standard access
roles:
  - mrn: "mrn:iam:role:developer"
    annotations:
      max_data_size: "1GB"
      can_export: "false"

# Platform team members can export
groups:
  - mrn: "mrn:iam:group:platform-team"
    annotations:
      can_export: "true"           # Override for this group
```

#### Layered Security Classifications

Apply cumulative security requirements:

```yaml
resource-groups:
  - mrn: "mrn:iam:resource-group:pii"
    annotations:
      classification: "PII"
      encryption_required: "true"

# Specific high-value resource
resource:
  annotations:
    classification: "PII-HIGH"     # More specific classification
    two_person_rule: "true"        # Additional requirement
```

## Annotation Structure

Keys must be strings. Values can be any valid JSON:

```json
{
  "annotations": {
    "department": "engineering",
    "cost_center": 12345,
    "tags": ["production", "critical"],
    "metadata": {
      "created_by": "admin",
      "version": 2
    },
    "enabled": true
  }
}
```

## Using Annotations in Policies

### Simple Value Checks

```rego
package authz

default allow = false

# Check department
allow {
    input.principal.mannotations.department == "engineering"
}

# Check resource tag
allow {
    input.resource.annotations.environment == "production"
}
```

### Array Annotations

```rego
package authz

default allow = false

# Principal must have required capability
allow {
    "admin" in input.principal.mannotations.capabilities
}

# Resource must have matching tag
allow {
    some tag in input.resource.annotations.tags
    tag in input.principal.mannotations.allowed_tags
}
```

### Nested Annotations

```rego
package authz

default allow = false

# Check nested value
allow {
    input.resource.annotations.metadata.level >= 2
}
```

### Matching Annotations

```rego
package authz

default allow = false

# Principal and resource department must match
allow {
    input.principal.mannotations.department == input.resource.annotations.department
}

# Principal must have access to resource's region
allow {
    input.resource.annotations.region in input.principal.mannotations.allowed_regions
}
```

## Defining Annotations in PolicyDomain

### On Roles

```yaml
spec:
  roles:
    - mrn: "mrn:iam:role:regional-admin"
      name: regional-admin
      annotations:
        region: "us-west"
        permissions: '["read", "write", "admin"]'
      policy: "mrn:iam:policy:regional-access"
```

### On Groups

```yaml
spec:
  groups:
    - mrn: "mrn:iam:group:finance"
      name: finance
      annotations:
        department: "finance"
        cost_center: "12345"
      roles:
        - "mrn:iam:role:finance-user"
```

### On Resource Groups

```yaml
spec:
  resource-groups:
    - mrn: "mrn:iam:resource-group:pii-data"
      name: pii-data
      annotations:
        data_classification: "PII"
        retention_days: "365"
        requires_audit: "true"
      policy: "mrn:iam:policy:pii-access"
```

## Common Annotation Patterns

### Department/Team Access

```rego
package authz

default allow = false

# Same department access
allow {
    input.principal.mannotations.department == input.resource.annotations.department
}
```

### Geographic Restrictions

```rego
package authz

default allow = false

# Principal's region must include resource's region
allow {
    input.resource.annotations.region in input.principal.mannotations.allowed_regions
}
```

### Time-Based Annotations

```rego
package authz

default allow = false

# Check if access hasn't expired
allow {
    expires := time.parse_rfc3339_ns(input.resource.annotations.access_expires)
    expires > time.now_ns()
}
```

### Feature Flags

```rego
package authz

default allow = false

# Check feature flag
allow {
    input.principal.mannotations.beta_features == true
    startswith(input.operation, "beta:")
}
```

## Best Practices

1. **Use consistent keys**: Establish naming conventions across all entity types
2. **Keep values simple**: Prefer primitives over complex objects
3. **Don't store sensitive data**: Annotations are not encrypted
4. **Document annotations**: Maintain a reference of used annotations and their expected sources
5. **Validate at ingestion**: Ensure annotation values are valid before storage
6. **Design for inheritance**: Place default values at lower precedence levels (roles, resource groups) and overrides at higher levels
7. **Be explicit about precedence**: When the same key appears at multiple levels, document the intended override behavior
8. **Avoid deep nesting**: While nested objects are supported, flatter structures are easier to reason about in policies

## Related Concepts

- **[Roles](/concepts/roles)**: Can define annotations inherited by principals
- **[Groups](/concepts/groups)**: Can define annotations that override role annotations
- **[Scopes](/concepts/scopes)**: Can define annotations that override group annotations
- **[Resources](/concepts/resources)**: Can have annotations that override resource group defaults
