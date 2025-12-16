---
sidebar_position: 8
---

# Scopes

**Scopes** provide an additional policy phase that allows MPE users to further constrain access decisions without modifying identity or resource policies. They represent a mechanism to apply contextual limitations based on the means of access rather than the identity itself.

## Overview

While identity policies determine what a principal *can* do based on their roles, scopes allow you to add an additional layer of constraint based on *how* the principal is accessing the system. This separation enables powerful access patterns where the same identity can have different effective permissions depending on the access context.

### Key Characteristics

- **Decoupled from Identity**: Scopes constrain access without requiring the identity phase to be aware of limitations
- **Access-Method Driven**: Typically associated with the means of access (tokens, API keys, federation)
- **Additive Constraints**: Scopes can only further restrict access, never expand it beyond what identity policies allow
- **Optional Phase**: If no scopes are present in a request, the scope phase defaults to GRANT

## Common Use Cases

### Personal Access Tokens (PAT)

Consider a user with roles A, B, and C that grant full read/write access. When that user creates a Personal Access Token for use in a CI/CD pipeline, they may want to limit what that token can do:

```
User Identity: Roles A, B, C → Full read/write access
PAT Scope: "read-only" → Constrains to read operations only

Effective Access: Read-only (intersection of identity and scope)
```

The PAT grants the caller the entitlements of Roles A, B, or C, but constrained by the additional "read-only" policy. This allows users to create limited-privilege tokens without modifying their underlying roles.

### Federated Access

When integrating with external identity providers or federation systems, scopes can constrain what federated sessions can do:

```
Federated User: Full internal permissions
Federation Scope: "external-api-only" → Limits to specific API subset

Effective Access: Only external API operations
```

### Service-to-Service Communication

Internal services may need different access levels depending on the calling context:

```
Service Identity: Full service permissions
Request Scope: "batch-processing" → Limits to batch operations only

Effective Access: Batch operations only
```

### OAuth Integration

While scopes are not tied to OAuth, they can be populated from OAuth token claims when using OAuth-based authentication:

```
OAuth Token Scopes: ["api:read", "api:write"]
MPE Scope Policies: Applied based on token claims

Effective Access: Constrained by OAuth scope policies
```

## How Scopes Work

### Phase 4 Evaluation

Scopes are evaluated in **Phase 4** of [Policy Conjunction](/concepts/policy-conjunction). The scope phase runs in parallel with other phases but has unique behavior:

| Condition | Scope Phase Result |
|-----------|-------------------|
| No scopes in PORC | **GRANT** (phase is skipped) |
| Scopes present, at least one GRANT | **GRANT** |
| Scopes present, all DENY | **DENY** |

### Multiple Scopes

When a request includes multiple scopes, each scope's policy is evaluated independently:

```
Request Scopes: ["read-only", "internal-api"]

Scope Evaluations:
├── read-only policy → GRANT (operation is a read)
├── internal-api policy → GRANT (target is internal)

Scope Phase Result: GRANT (at least one GRANT)
```

This OR relationship within the scope phase means that if any applicable scope policy grants access, the phase votes GRANT.

## Scopes vs. Roles

Understanding the difference between scopes and roles is crucial:

| Aspect | Roles (Identity Phase) | Scopes (Scope Phase) |
|--------|----------------------|---------------------|
| **Purpose** | Define what a principal can do | Constrain how access is exercised |
| **Assignment** | Assigned to principals | Associated with access method |
| **Effect** | Grant permissions | Limit permissions |
| **Mandatory** | Yes (Phase 2) | No (Phase 4) |
| **Default** | DENY if missing | GRANT if missing |

### Example: Role vs. Scope Interaction

```
Principal: admin role (can read, write, delete)
Access Token Scope: read-only

Identity Phase: GRANT (admin can delete)
Scope Phase: DENY (read-only forbids delete)

Final Decision: DENY (scope constrains identity)
```

## Defining Scopes

Scopes are defined in the PolicyDomain under `spec.scopes`:

```yaml
spec:
  scopes:
    - mrn: "mrn:iam:scope:read-only"
      name: read-only
      description: "Restricts to read operations only"
      policy: "mrn:iam:policy:read-only-check"

    - mrn: "mrn:iam:scope:internal"
      name: internal
      description: "Internal system access"
      policy: "mrn:iam:policy:internal-only"
```

Each scope references a policy that determines whether the scope allows or denies the operation.

## Populating Scopes in PORC

Scopes appear in the PORC expression based on how the request was authenticated:

```yaml
principal:
  sub: "user123"
  mroles:
    - "mrn:iam:role:editor"
context:
  scopes:
    - "mrn:iam:scope:read-only"
operation: "api:documents:update"
resource:
  mrn: "mrn:data:document:doc456"
```

The integration layer (PEP) is responsible for extracting scope information from the access token or authentication context and including it in the PORC.

## Best Practices

### 1. Design Scope Policies for Constraint

Scope policies should focus on what to *restrict*, not what to *allow*:

```rego
# Good: Scope constrains to read operations
package authz
default grant = false
grant {
    input.operation.method == "read"
}

# Avoid: Scope tries to grant broad access
# (This defeats the purpose of scopes as constraints)
```

### 2. Use Clear Scope Naming

Name scopes based on their constraint, not their source:

```yaml
# Good: Describes the constraint
- name: read-only
- name: batch-processing
- name: external-api

# Avoid: Describes the source
- name: pat-scope
- name: oauth-scope
```

### 3. Document Scope Requirements

Clearly document which scopes are expected for different access methods:

| Access Method | Required Scopes | Notes |
|--------------|-----------------|-------|
| PAT | At least one scope | User selects at creation |
| OAuth | From token claims | Mapped from OAuth scopes |
| Internal API | None | Full access |

### 4. Monitor Scope Denials

Track when scope policies deny access—this can indicate:
- Tokens with insufficient scopes for the operation
- Misconfigured scope policies
- Users attempting operations beyond their token's authorization

### 5. Leverage Annotations for Scope Metadata

Scopes can carry [annotations](/concepts/annotations) that flow to principals during evaluation. Scope annotations have higher precedence than both role and group annotations, making them useful for access-method-specific metadata:

```yaml
scopes:
  - mrn: "mrn:iam:scope:elevated-access"
    name: elevated-access
    description: "Elevated access for sensitive operations"
    policy: "mrn:iam:policy:elevated-check"
    annotations:
      access_level: "elevated"
      audit_required: "true"
      session_type: "privileged"
```

In the inheritance hierarchy (Roles → Groups → **Scopes** → Principal), scope annotations override any conflicting values from roles or groups. This allows you to apply context-specific metadata based on how the principal is accessing the system.

## Related Concepts

- **[Roles](/concepts/roles)**: Identity-based permissions (lower annotation precedence)
- **[Groups](/concepts/groups)**: Role aggregation (lower annotation precedence)
- **[Annotations](/concepts/annotations)**: Metadata inheritance hierarchy
- **[Policy Conjunction](/concepts/policy-conjunction)**: How scopes fit into multi-phase evaluation
- **[Policies](/concepts/policies)**: Writing the Rego policies that scopes reference
- **[PORC Expressions](/concepts/porc)**: How scopes are represented in requests

For schema details, see the [Scopes Schema Reference](/reference/schema/scopes).
