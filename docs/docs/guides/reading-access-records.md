---
sidebar_position: 1
---

# Reading Access Records

This guide explains how to interpret the human-readable AccessRecord output from the PolicyEngine, helping you understand exactly what happened during a policy evaluation.

## Overview

Every authorization decision generates an AccessRecord that captures the complete evaluation context. While the [AccessRecord Schema Reference](/reference/access-record) documents the structure, this guide walks through practical examples to help you understand what you're seeing.

You'll want to read AccessRecords when:

- Debugging why a request was denied (or granted unexpectedly)
- Auditing access patterns for compliance
- Understanding which policies are being triggered
- Tracing the evaluation path through conjunction phases

## Enabling Pretty-Print Output

By default, AccessRecords are emitted as compact single-line JSON. For human readability, use the `--pretty-log` flag:

```bash
mpe serve -b my-domain.yml --pretty-log
```

### Compact vs Pretty Output

**Compact (default):**
```json
{"metadata":{"timestamp":"2024-01-15T10:30:00Z","id":"550e8400-e29b-41d4-a716-446655440000"},"principal":{"subject":"alice@example.com","realm":"employees"},"operation":"api:documents:read","resource":"mrn:app:document:12345","decision":"GRANT","references":[...],"porc":"{...}"}
```

**Pretty (`--pretty-log`):**
```json
{
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "id": "550e8400-e29b-41d4-a716-446655440000"
  },
  "principal": {
    "subject": "alice@example.com",
    "realm": "employees"
  },
  "operation": "api:documents:read",
  "resource": "mrn:app:document:12345",
  "decision": "GRANT",
  "references": [...],
  "porc": {
    "principal": {...},
    "operation": "api:documents:read",
    ...
  }
}
```

Note that `--pretty-log` also expands the `porc` field from a JSON string into a proper JSON object, making it much easier to inspect.

## Anatomy of an AccessRecord

### Top-Level Fields at a Glance

| Field | Description |
|-------|-------------|
| `metadata` | Timestamp, unique ID, and environment context |
| `principal` | The authenticated subject making the request |
| `operation` | The operation being attempted |
| `resource` | The resource MRN being accessed |
| `decision` | Final outcome: `GRANT` or `DENY` |
| `references` | Array of bundle evaluations (the evaluation story) |
| `porc` | The complete PORC expression that was evaluated |
| `system_override` | Whether a system bypass occurred |
| `grant_reason` / `deny_reason` | Bypass reason when `system_override` is true |

### The References Array: Understanding the Evaluation Story

The `references` array is the heart of debugging—it shows every policy bundle that was evaluated and how each contributed to the final decision.

Each entry in the array is a **BundleReference** with these fields:

| Field | Description |
|-------|-------------|
| `id` | Operation name (e.g., `api:documents:update`) or MRN (e.g., `mrn:iam:role:editor`) |
| `phase` | Which conjunction phase: `SYSTEM`, `IDENTITY`, `RESOURCE`, or `SCOPE` |
| `decision` | This bundle's outcome: `GRANT` or `DENY` |
| `reason_code` | `POLICY_OUTCOME` for normal evaluation, or an error code |
| `reason` | Human-readable explanation (especially useful for errors or denials) |
| `policies` | Array of exact policy versions evaluated (MRN + fingerprint) |

:::note Phase Naming
In AccessRecords, the **Operation phase** appears as `SYSTEM` in the `phase` field. This reflects the internal protobuf naming. When you see `"phase": "SYSTEM"`, think "Operation phase."
:::

### The PORC Field

The `porc` field contains the complete input that was evaluated. With `--pretty-log`, it's expanded from a JSON string into a readable object:

```json
"porc": {
  "principal": {
    "sub": "user123",
    "mroles": ["mrn:iam:role:editor", "mrn:iam:role:viewer"],
    "scopes": ["mrn:iam:scope:documents", "mrn:iam:scope:read-only"]
  },
  "operation": "api:documents:update",
  "resource": {
    "id": "mrn:data:document:doc456",
    "owner": "user123",
    "group": "mrn:iam:resource-group:owner-exclusive"
  },
  "context": {}
}
```

This is invaluable for correlating inputs with outputs—you can see exactly what principal attributes, roles, and scopes were present when the decision was made.

## Example: Tracing a Document Update Request

Let's walk through a complete example based on a document update scenario.

### The Scenario

- **User**: `user123` with two roles: `editor` and `viewer`
- **Operation**: `api:documents:update`
- **Resource**: A document owned by `user123` in the `owner-exclusive` resource group
- **Scopes**: `documents` and `read-only`

### The Full AccessRecord (Annotated)

```json
{
  "metadata": {
    "timestamp": "2024-01-15T10:30:00.123Z",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "env": {
      "service": "document-service",
      "environment": "production"
    }
  },
  "principal": {
    "subject": "user123",
    "realm": "employees"
  },
  "operation": "api:documents:update",
  "resource": "mrn:data:document:doc456",
  "decision": "GRANT",
  "references": [
    {
      "id": "api:documents:update",
      "policies": [
        {
          "mrn": "mrn:iam:policy:require-authenticated",
          "fingerprint": "YTNmMmI4YzE..."
        }
      ],
      "decision": "GRANT",
      "phase": "SYSTEM",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:role:editor",
      "policies": [
        {
          "mrn": "mrn:iam:policy:editor-permissions",
          "fingerprint": "ZDRlNWY2YTc..."
        }
      ],
      "decision": "GRANT",
      "phase": "IDENTITY",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:role:viewer",
      "policies": [
        {
          "mrn": "mrn:iam:policy:viewer-permissions",
          "fingerprint": "YjJjM2Q0ZTU..."
        }
      ],
      "decision": "DENY",
      "phase": "IDENTITY",
      "reason_code": "POLICY_OUTCOME",
      "reason": "viewer role does not permit update operations"
    },
    {
      "id": "mrn:iam:resource-group:owner-exclusive",
      "policies": [
        {
          "mrn": "mrn:iam:policy:owner-only",
          "fingerprint": "M2E0YjVjNmQ..."
        }
      ],
      "decision": "GRANT",
      "phase": "RESOURCE",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:scope:documents",
      "policies": [
        {
          "mrn": "mrn:iam:policy:documents-scope",
          "fingerprint": "N2I4YzlkMGU..."
        }
      ],
      "decision": "GRANT",
      "phase": "SCOPE",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:scope:read-only",
      "policies": [
        {
          "mrn": "mrn:iam:policy:read-only-scope",
          "fingerprint": "OGM5ZDFlMmY..."
        }
      ],
      "decision": "DENY",
      "phase": "SCOPE",
      "reason_code": "POLICY_OUTCOME",
      "reason": "read-only scope does not permit update operations"
    }
  ],
  "porc": {
    "principal": {
      "sub": "user123",
      "mroles": ["mrn:iam:role:editor", "mrn:iam:role:viewer"],
      "scopes": ["mrn:iam:scope:documents", "mrn:iam:scope:read-only"]
    },
    "operation": "api:documents:update",
    "resource": {
      "id": "mrn:data:document:doc456",
      "owner": "user123",
      "group": "mrn:iam:resource-group:owner-exclusive"
    },
    "context": {}
  },
  "system_override": false
}
```

### Breaking Down the Evaluation

**1. Operation Phase (`SYSTEM`)**: <DecisionChip decision="grant" />

The `require-authenticated` policy verified the request is authenticated. Phase result: **GRANT**.

**2. Identity Phase**: <DecisionChip decision="grant" />

Two roles were evaluated:
- `editor` → <DecisionChip decision="grant" /> (can update documents)
- `viewer` → <DecisionChip decision="deny" /> (read-only role)

Phase result: **GRANT** (only one GRANT needed within a phase)

**3. Resource Phase**: <DecisionChip decision="grant" />

The `owner-exclusive` resource group policy verified the user owns the document. Phase result: **GRANT**.

**4. Scope Phase**: <DecisionChip decision="grant" />

Two scopes were evaluated:
- `documents` → <DecisionChip decision="grant" /> (document operations allowed)
- `read-only` → <DecisionChip decision="deny" /> (no write operations)

Phase result: **GRANT** (only one GRANT needed within a phase)

**5. Final Decision**: <DecisionChip decision="grant" />

All phases have at least one GRANT, so access is granted.

### Key Insight: OR Within Phases, AND Across Phases

Notice that both the `viewer` role and the `read-only` scope voted DENY, but the request was still granted. This is because:

- **Within a phase**: Only one GRANT is needed (OR semantics)
- **Across phases**: All phases must have at least one GRANT (AND semantics)

The `editor` role provided the necessary GRANT for the Identity phase, and the `documents` scope provided the necessary GRANT for the Scope phase. For more details, see [Policy Conjunction](/concepts/policy-conjunction).

## Common Patterns

### Multiple DENYs in Identity Phase, Overall GRANT

This is normal and expected. A user might have multiple roles, but only one needs to permit the operation:

```json
"references": [
  { "id": "mrn:iam:role:guest", "decision": "DENY", "phase": "IDENTITY" },
  { "id": "mrn:iam:role:member", "decision": "DENY", "phase": "IDENTITY" },
  { "id": "mrn:iam:role:admin", "decision": "GRANT", "phase": "IDENTITY" }
]
```

Phase result: GRANT (the admin role was sufficient)

### COMPILATION_ERROR or NOTFOUND_ERROR

When a policy fails to load or compile, you'll see an error code:

```json
{
  "id": "mrn:iam:role:custom",
  "decision": "DENY",
  "phase": "IDENTITY",
  "reason_code": "COMPILATION_ERROR",
  "reason": "rego_type_error: undefined ref: data.policy.custom_rule"
}
```

This bundle is treated as DENY for safety. Check:
- Is the policy MRN correct?
- Does the policy file exist in the bundle?
- Are there syntax errors in the Rego code?

### system_override: true

When `system_override` is true, the normal policy evaluation was bypassed:

```json
{
  "decision": "GRANT",
  "system_override": true,
  "grant_reason": "PUBLIC"
}
```

This means the resource or operation is marked as public, so no policy evaluation was needed. Other reasons include `VISITOR` (visitor access permitted) and `ANTI_LOCKOUT` (anti-lockout protection triggered).

For denials, you might see `JWT_REQUIRED` or `OPERATOR_REQUIRED`.

## Quick Debugging Guide

### "Why Was My Request Denied?"

1. **Find the AccessRecord** for the denied request (filter by principal and timestamp)

2. **Check for system_override**:
   - If `system_override: true`, check `deny_reason` for the cause (e.g., `JWT_REQUIRED`)

3. **Scan the references array**:
   - Look for the first phase where NO bundle has `decision: "GRANT"`
   - That's the phase that caused the denial

4. **Within that phase**, examine each bundle:
   - Check `reason_code` for errors (`COMPILATION_ERROR`, `NOTFOUND_ERROR`)
   - Check `reason` for human-readable explanations

5. **Correlate with policy code**:
   - Use the `mrn` and `fingerprint` to identify the exact policy version
   - Review the policy logic to understand why it denied

:::tip Deep Debugging
If the AccessRecord shows which policy denied but you need to understand *why*, enable trace output with `mpe --trace`. See [Debugging Policies](/guides/debugging-policies) for interpreting the trace.
:::

### Finding Which Phase Failed

Scan through the references and group by phase. A request is denied when a mandatory phase has no GRANT votes:

| Phase | Mandatory | Has GRANT? | Result |
|-------|-----------|------------|--------|
| SYSTEM (Operation) | Yes | No | **Request denied** |
| IDENTITY | Yes | No | **Request denied** |
| RESOURCE | Yes | No | **Request denied** |
| SCOPE | Only if scopes present | No | **Request denied** |

### Correlating with Policy Code

Each policy reference includes a fingerprint—a cryptographic hash of the policy content. This lets you identify the exact version that was evaluated, even if the policy has since been updated:

```json
{
  "mrn": "mrn:iam:policy:editor-permissions",
  "fingerprint": "ZDRlNWY2YTc..."
}
```

If you're investigating a historical decision, you can compare this fingerprint against your policy version history.

## Quick Reference Tables

### Phase Values

| AccessRecord Value | Conjunction Phase | Description |
|-------------------|-------------------|-------------|
| `SYSTEM` | Operation | Coarse-grained request control |
| `IDENTITY` | Identity | Role-based policies |
| `RESOURCE` | Resource | Resource group policies |
| `SCOPE` | Scope | Access-method constraints |

### ReasonCode Values

| Code | Meaning |
|------|---------|
| `POLICY_OUTCOME` | Normal policy evaluation completed |
| `COMPILATION_ERROR` | Policy failed to compile (Rego syntax error) |
| `NOTFOUND_ERROR` | Referenced policy could not be found |
| `NETWORK_ERROR` | Network issue prevented policy resolution |
| `EVALUATION_ERROR` | OPA evaluation error during execution |
| `INVALPARAM_ERROR` | Invalid parameter or identifier |
| `UNKNOWN_ERROR` | Unspecified error |

## Related Resources

- [AccessRecord Schema Reference](/reference/access-record) — Complete field definitions and types
- [Policy Conjunction](/concepts/policy-conjunction) — How phases combine to reach decisions
- [Audit & Access Records](/concepts/audit) — Conceptual overview and use cases
- [Debugging Policies](/guides/debugging-policies) — Interpreting OPA trace output
- [PORC](/concepts/porc) — The input format captured in AccessRecords
