---
sidebar_position: 5
---

# Roles

**Roles** define the identity-based access permissions for principals in your system. They are the primary mechanism for determining what actions a user or service can perform and are evaluated during Phase 2 (Identity Phase) of [Policy Conjunction](/concepts/policy-conjunction).

## Overview

A role connects a principal's identity to a policy. When a principal is assigned a role, the role's associated policy is evaluated to determine whether the principal can perform the requested operation. Roles answer the question: *"Based on who this principal is, what are they allowed to do?"*

### Key Characteristics

- **Identity-Centric**: Roles are assigned to principals (users, services) to define their capabilities
- **Policy-Backed**: Each role references exactly one policy that contains the access logic
- **Mandatory Phase**: The identity phase (Phase 2) must contribute at least one GRANT for access to be allowed
- **Additive Permissions**: A principal can have multiple roles, and only one needs to grant access

## How Roles Work

### Phase 2 Evaluation

Roles are evaluated in **Phase 2** (Identity Phase) of [Policy Conjunction](/concepts/policy-conjunction). When a request arrives:

1. The principal's roles are extracted from their JWT claims (`mroles`)
2. Each role's associated policy is evaluated against the request
3. If **any** role policy grants access, the identity phase votes GRANT

```
Principal with roles: [editor, viewer]

Identity Phase Evaluation:
├── editor role policy → GRANT (can edit documents)
├── viewer role policy → DENY (read-only)

Identity Phase Result: GRANT (at least one role granted)
```

### Multiple Roles

When a principal has multiple roles, the policies are evaluated with OR semantics within the phase:

| Role Evaluations | Phase Result |
|-----------------|--------------|
| All DENY | DENY |
| At least one GRANT | GRANT |

This means permissions are effectively additive—a principal gains the union of all their roles' permissions.

## Defining Roles

Roles are defined in the PolicyDomain under `spec.roles`:

```yaml
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      description: "Full administrative access"
      policy: "mrn:iam:policy:allow-all"

    - mrn: "mrn:iam:role:editor"
      name: editor
      description: "Can create and modify content"
      policy: "mrn:iam:policy:editor-access"

    - mrn: "mrn:iam:role:viewer"
      name: viewer
      description: "Read-only access"
      policy: "mrn:iam:policy:read-only"
```

Each role requires:
- **mrn**: A unique identifier following the MRN format
- **name**: Human-readable name
- **policy**: MRN of the policy to evaluate when this role is present

## Assigning Roles to Principals

Roles are assigned to principals via JWT claims. The PolicyEngine expects roles in the `mroles` claim:

```yaml
# PORC expression showing role assignment
principal:
  sub: "user123"
  mroles:
    - "mrn:iam:role:editor"
    - "mrn:iam:role:viewer"
```

The integration layer (PEP) is responsible for extracting role information from the authentication token and including it in the PORC.

### Direct Assignment vs. Groups

Roles can be assigned to principals in two ways:

1. **Direct Assignment**: Roles listed directly in the `mroles` JWT claim
2. **Group Membership**: Roles inherited through [Groups](/concepts/groups) via the `mgroups` claim

Using groups simplifies management when many principals share the same set of roles.

## Common Role Patterns

### Hierarchical Roles

Create roles with increasing levels of access:

```yaml
roles:
  - mrn: "mrn:iam:role:viewer"
    name: viewer
    policy: "mrn:iam:policy:read-only"

  - mrn: "mrn:iam:role:editor"
    name: editor
    policy: "mrn:iam:policy:read-write"

  - mrn: "mrn:iam:role:admin"
    name: admin
    policy: "mrn:iam:policy:full-access"
```

### Functional Roles

Organize roles by business function:

```yaml
roles:
  - mrn: "mrn:iam:role:finance-user"
    name: finance-user
    policy: "mrn:iam:policy:finance-access"

  - mrn: "mrn:iam:role:hr-user"
    name: hr-user
    policy: "mrn:iam:policy:hr-access"

  - mrn: "mrn:iam:role:engineering-user"
    name: engineering-user
    policy: "mrn:iam:policy:engineering-access"
```

### Service Roles

Define roles for service accounts and automated processes:

```yaml
roles:
  - mrn: "mrn:iam:role:batch-processor"
    name: batch-processor
    description: "Automated batch processing service"
    policy: "mrn:iam:policy:batch-operations"

  - mrn: "mrn:iam:role:monitoring-agent"
    name: monitoring-agent
    description: "System monitoring service"
    policy: "mrn:iam:policy:monitoring-read"
```

## Roles vs. Scopes

Understanding the difference between roles and scopes is important:

| Aspect | Roles (Identity Phase) | Scopes (Scope Phase) |
|--------|----------------------|---------------------|
| **Purpose** | Define what a principal can do | Constrain how access is exercised |
| **Assignment** | Assigned to principals | Associated with access method |
| **Effect** | Grant permissions | Limit permissions |
| **Mandatory** | Yes (Phase 2) | No (Phase 4) |
| **Default** | DENY if missing | GRANT if missing |

### Example: Role and Scope Interaction

```
Principal: admin role (can read, write, delete)
Access Token Scope: read-only

Identity Phase (roles): GRANT (admin can delete)
Scope Phase: DENY (read-only forbids delete)

Final Decision: DENY (all mandatory phases must agree)
```

Roles define the maximum permissions; scopes can only restrict, never expand.

## Using Role Information in Policies

Access role information in Rego via `input.principal.mroles`:

```rego
package authz

default allow = false

# Allow if principal has admin role
allow {
    "mrn:iam:role:admin" in input.principal.mroles
}

# Allow read operations for viewers
allow {
    "mrn:iam:role:viewer" in input.principal.mroles
    input.operation.method == "read"
}

# Check for any of multiple roles
allow {
    allowed_roles := {"mrn:iam:role:editor", "mrn:iam:role:admin"}
    some role in input.principal.mroles
    role in allowed_roles
}
```

## Best Practices

### 1. Follow Least Privilege

Assign the minimum roles necessary for each principal to perform their function:

```yaml
# Good: Specific role for specific function
- mrn: "mrn:iam:role:report-viewer"
  policy: "mrn:iam:policy:reports-read"

# Avoid: Overly broad role
- mrn: "mrn:iam:role:super-user"
  policy: "mrn:iam:policy:allow-all"
```

### 2. Use Descriptive Names

Name roles based on their purpose, not their technical implementation:

```yaml
# Good: Describes the business role
- name: content-editor
- name: billing-admin

# Avoid: Technical or generic names
- name: role1
- name: policy-evaluator
```

### 3. Document Role Purpose

Include descriptions to clarify what each role is for:

```yaml
roles:
  - mrn: "mrn:iam:role:data-steward"
    name: data-steward
    description: "Can manage data classifications and retention policies"
    policy: "mrn:iam:policy:data-governance"
```

### 4. Consider Role Granularity

Balance between too many fine-grained roles and too few coarse roles:

- **Too fine**: Hundreds of roles become unmanageable
- **Too coarse**: Principals get more access than needed
- **Just right**: Roles align with business functions and responsibilities

### 5. Use Groups for Common Role Sets

When multiple principals need the same set of roles, use [Groups](/concepts/groups) instead of assigning roles individually.

### 6. Leverage Annotations for Metadata

Roles can carry [annotations](/concepts/annotations) that flow to the principal during evaluation:

```yaml
roles:
  - mrn: "mrn:iam:role:regional-admin"
    name: regional-admin
    policy: "mrn:iam:policy:regional-access"
    annotations:
      - name: "region"
        value: "\"us-west\""
      - name: "access_level"
        value: "\"admin\""
```

Role annotations have the lowest precedence in the identity annotation hierarchy (Roles → Groups → Scopes → Principal). This makes them ideal for establishing default metadata that can be overridden by more specific sources.

## Related Concepts

- **[Groups](/concepts/groups)**: Organize multiple roles for easier assignment
- **[Annotations](/concepts/annotations)**: Metadata that can be attached to roles (lowest precedence in identity hierarchy)
- **[Policy Conjunction](/concepts/policy-conjunction)**: How roles fit into multi-phase evaluation
- **[Policies](/concepts/policies)**: Writing the Rego policies that roles reference
- **[Scopes](/concepts/scopes)**: Additional constraints beyond identity-based access

For schema details, see the [Roles Schema Reference](/reference/schema/roles).
