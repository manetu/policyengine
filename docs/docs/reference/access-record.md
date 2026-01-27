---
sidebar_position: 3
---

# AccessRecord Schema

Complete reference for the AccessRecord structure emitted by the Policy Decision Point (PDP) for every authorization decision.

## Overview

The AccessRecord captures the complete context of a policy evaluation, enabling audit, debugging, analytics, and policy replay.

| Output         | Availability                        | Description                                    |
|----------------|-------------------------------------|------------------------------------------------|
| JSON to stdout | <FeatureChip variant="community" /> | Stream records for custom processing pipelines |
| ElasticSearch  | <FeatureChip variant="premium" />   | Durable storage with indexing and analytics    |

## Top-Level Structure

```json
{
  "metadata": { ... },
  "principal": { ... },
  "operation": "string",
  "resource": "string",
  "decision": "GRANT | DENY",
  "references": [ ... ],
  "porc": "string",
  "system_override": false,
  "grant_reason": "...",
  "deny_reason": "..."
}
```

## Fields

### metadata

Contextual information about the decision.

| Field       | Type              | Description                                     |
|-------------|-------------------|-------------------------------------------------|
| `timestamp` | string (ISO 8601) | When the decision was made                      |
| `id`        | string (UUID)     | Unique identifier for this record               |
| `env`       | object            | Optional key-value pairs for deployment context |

**Example:**

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "env": {
    "service": "api-gateway",
    "pod": "api-gw-7d9f8b6c4-x2m9k",
    "region": "us-east-1"
  }
}
```

### principal

The authenticated subject making the request.

| Field     | Type   | Description                                               |
|-----------|--------|-----------------------------------------------------------|
| `subject` | string | The principal identifier (e.g., user ID, service account) |
| `realm`   | string | The authentication realm or domain                        |

**Example:**

```json
{
  "subject": "alice@example.com",
  "realm": "employees"
}
```

### operation

The operation being attempted, from the PORC expression.

**Type:** string

**Example:** `"api:documents:read"`, `"http-post"`, `"graphql-mutate"`

### resource

The resource MRN being accessed, from the PORC expression.

**Type:** string

**Example:** `"mrn:app:document:12345"`, `"mrn:http:/api/users"`

### decision

The top-level authorization outcome.

**Type:** enum

| Value   | Description          |
|---------|----------------------|
| `GRANT` | Access was permitted |
| `DENY`  | Access was denied    |

### references

Array of policy bundle references detailing each policy evaluated during the decision.

See [BundleReference](#bundlereference) below.

### porc

The complete PORC expression that was evaluated, serialized as JSON.

**Type:** string (JSON)

This field enables policy replay—you can deserialize this value and re-evaluate it against different policy versions to understand how changes would affect decisions.

### system_override

Indicates whether the decision was made by a system-level bypass rather than normal policy evaluation.

**Type:** boolean

When `true`, check `grant_reason` or `deny_reason` for the bypass type.

### grant_reason / deny_reason

When `system_override` is true, indicates why the bypass occurred.

**Grant Reasons:**

| Value          | Description                       |
|----------------|-----------------------------------|
| `PUBLIC`       | Resource is marked as public      |
| `VISITOR`      | Visitor access is permitted       |
| `ANTI_LOCKOUT` | Anti-lockout protection triggered |

**Deny Reasons:**

| Value               | Description                             |
|---------------------|-----------------------------------------|
| `JWT_REQUIRED`      | A valid JWT is required but not present |
| `OPERATOR_REQUIRED` | Operator-level access is required       |

## BundleReference

Each policy bundle evaluated during the decision is recorded as a BundleReference.

```json
{
  "id": "string",
  "policies": [ ... ],
  "decision": "GRANT | DENY",
  "phase": "OPERATION | IDENTITY | RESOURCE | SCOPE",
  "reason_code": "...",
  "reason": "string"
}
```

### Fields

| Field         | Type   | Description                                       |
|---------------|--------|---------------------------------------------------|
| `id`          | string | Operation name or role MRN                        |
| `policies`    | array  | List of PolicyReference objects                   |
| `decision`    | enum   | Outcome of this bundle: `GRANT` or `DENY`         |
| `phase`       | enum   | Which conjunction phase (see below)               |
| `reason_code` | enum   | Success or error type (see below)                 |
| `reason`      | string | Human-readable explanation, especially for errors |

### Phase

Indicates which [conjunction phase](/concepts/policy-conjunction) the bundle belongs to.

| Value       | Description                        |
|-------------|------------------------------------|
| `OPERATION` | Phase 1: Operation-level policies  |
| `IDENTITY`  | Phase 2: Role-based policies       |
| `RESOURCE`  | Phase 3: Resource group policies   |
| `SCOPE`     | Phase 4: Scope constraint policies |

### ReasonCode

Indicates the evaluation outcome type.

| Value               | Description                               |
|---------------------|-------------------------------------------|
| `POLICY_OUTCOME`    | Normal policy evaluation completed        |
| `COMPILATION_ERROR` | Policy failed to compile                  |
| `NOTFOUND_ERROR`    | Referenced policy could not be found      |
| `NETWORK_ERROR`     | Network issue prevented policy resolution |
| `EVALUATION_ERROR`  | OPA evaluation error (not compilation)    |
| `INVALPARAM_ERROR`  | Invalid parameter or identifier           |
| `UNKNOWN_ERROR`     | Unspecified error                         |

When `reason_code` is not `POLICY_OUTCOME`, the `reason` field typically contains details about the error.

## PolicyReference

Individual policy identification within a bundle.

```json
{
  "mrn": "string",
  "fingerprint": "bytes"
}
```

| Field         | Type   | Description                                      |
|---------------|--------|--------------------------------------------------|
| `mrn`         | string | The policy's Manetu Resource Notation identifier |
| `fingerprint` | bytes  | Cryptographic hash of the policy content         |

The combination of `mrn` and `fingerprint` uniquely identifies the exact policy version that was evaluated. This is critical for forensic analysis—even after policies are updated, you can determine exactly which version produced a particular decision.

## Complete Example

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
    "subject": "alice@example.com",
    "realm": "corporate"
  },
  "operation": "api:documents:update",
  "resource": "mrn:app:document:confidential-report-2024",
  "decision": "DENY",
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
      "phase": "OPERATION",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:role:editor",
      "policies": [
        {
          "mrn": "mrn:iam:policy:editor-access",
          "fingerprint": "ZDRlNWY2YTc..."
        }
      ],
      "decision": "GRANT",
      "phase": "IDENTITY",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:resource-group:confidential",
      "policies": [
        {
          "mrn": "mrn:iam:policy:confidential-access",
          "fingerprint": "YjJjM2Q0ZTU..."
        }
      ],
      "decision": "DENY",
      "phase": "RESOURCE",
      "reason_code": "POLICY_OUTCOME",
      "reason": "Principal lacks 'confidential' clearance annotation"
    }
  ],
  "porc": "{\"principal\":{\"sub\":\"alice@example.com\",\"mroles\":[\"mrn:iam:role:editor\"]},\"operation\":\"api:documents:update\",\"resource\":\"mrn:app:document:confidential-report-2024\",\"context\":{}}",
  "system_override": false
}
```

In this example, the request passed Phase 1 (Operation) and Phase 2 (Identity), but was denied in Phase 3 (Resource) because the resource belongs to a confidential resource group and the principal lacks the required clearance.

## See Also

- [Reading Access Records](/guides/reading-access-records) — Practical guide to interpreting output
- [Audit & Access Records](/concepts/audit) — Conceptual overview and use cases
- [Policy Conjunction](/concepts/policy-conjunction) — How phases combine to reach decisions
- [PORC](/concepts/porc) — The input format that AccessRecords capture
