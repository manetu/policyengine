---
sidebar_position: 1
---

# Quick Start

This guide will walk you through creating your first PolicyDomain and testing policy decisions.

## Overview

In this quick start, you will:

1. Create a simple PolicyDomain with policies
2. Lint your PolicyDomain to validate syntax
3. Test policy decisions using the CLI

## What is a PolicyDomain?

A **[PolicyDomain](/concepts/policy-domains)** is a YAML file that bundles together all the policy-related artifacts for a specific domain or service:

- **[Policies](/concepts/policies)**: The Rego code that makes access control decisions
- **[Policy Libraries](/concepts/policy-libraries)**: Reusable code shared across policies
- **[Roles](/concepts/roles), [Groups](/concepts/groups), [Scopes](/concepts/scopes)**: Identity and permission mappings
- **[Resource Groups](/concepts/resource-groups)** and **[Resources](/concepts/resources)**: Resource-to-policy mappings
- **[Operations](/concepts/operations)** and **[Mappers](/concepts/mappers)**: Request routing and transformation

## Your First PolicyDomain

Create a file called `my-domain.yml`:

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
        default allow = 0  # operation policies use tri-level integers

    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Allows all authenticated requests"
      rego: |
        package authz
        default allow = false

        allow {
            input.principal != {}
        }

    - mrn: &deny-all "mrn:iam:policy:deny-all"
      name: deny-all
      description: "Denies all requests"
      rego: |
        package authz
        default allow = false

  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      description: "Administrator role with full access"
      policy: *allow-all

    - mrn: "mrn:iam:role:guest"
      name: guest
      description: "Guest role with no access"
      policy: *deny-all

  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      description: "Default resource group"
      default: true
      policy: *allow-all

  operations:
    - name: api
      selector:
        - ".*"
      policy: *operation-default
```

## Validating Your PolicyDomain

Use the `lint` command to validate your PolicyDomain:

```bash
mpe lint -f my-domain.yml
```

If everything is valid, you'll see:

```
Linting YAML files...

✓ my-domain.yml: Valid YAML
✓ my-domain.yml: Valid Rego in policy 'operation-default'
✓ my-domain.yml: Valid Rego in policy 'allow-all'
✓ my-domain.yml: Valid Rego in policy 'deny-all'
---
All checks passed: 1 file(s) validated successfully
```

## Testing Policy Decisions

See [Testing Policies](/quick-start/testing-policies) for detailed testing instructions.

## Next Steps

- [Creating Your First PolicyDomain](/quick-start/first-policy-domain) - Detailed walkthrough
- [Testing Policies](/quick-start/testing-policies) - Test your policies
- [Concepts](/concepts) - Understand the full model
