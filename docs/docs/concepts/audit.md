---
sidebar_position: 15
---

# Audit & Access Records

Every policy decision generates a normalized **AccessRecord** that captures the complete evaluation context. This audit trail is fundamental to understanding, debugging, and analyzing access control behavior across your system.

<div class="centered-image">
![PBAC Mindmap](./assets/audit.svg)
</div>

## Why Audit Matters

In distributed systems, access control decisions happen across many services, making it difficult to answer questions like:

- Why was this request denied?
- Which policies are being triggered most often?
- Are there unusual access patterns that might indicate a security issue?
- What would have happened if we had deployed a different policy version?

The AccessRecord stream solves these challenges by providing a consistent, structured record of every decision.

## The AccessRecord

Just as [PORC](/concepts/porc) normalizes authorization **inputs**, the AccessRecord normalizes authorization **outputs**. This symmetry allows you to reason about access control decisions consistently, regardless of where they originated in your system.

Every AccessRecord contains:

| Field | Description |
|-------|-------------|
| **Metadata** | Timestamp, unique ID, and optional environment context |
| **Principal** | The subject and realm from the PORC |
| **Operation** | The operation being attempted |
| **Resource** | The resource MRN being accessed |
| **Decision** | The top-level outcome: `GRANT` or `DENY` |
| **References** | Details about each policy bundle evaluated |
| **PORC** | The complete PORC expression for replay/debugging |

### Policy Bundle References

Each evaluated policy bundle is recorded with:

- **MRN**: The policy's Manetu Resource Notation identifier
- **Fingerprint**: A cryptographic hash of the policy content
- **Decision**: The outcome of this specific policy (`GRANT` or `DENY`)
- **Phase**: Which [conjunction phase](/concepts/policy-conjunction) (Operation, Identity, Resource, Scope)
- **Reason Code**: Success or specific error type
- **Reason**: Human-readable explanation (especially for errors)

The fingerprint is particularly valuable—it uniquely identifies the exact policy version evaluated, enabling precise forensic analysis even after policies are updated.

## Output Destinations

| Feature | Availability | Description |
|---------|--------------|-------------|
| JSON to stdout | <FeatureChip variant="oss" /> | Stream AccessRecords as JSON for custom processing |
| ElasticSearch Integration | <FeatureChip variant="premium" /> | Durable storage with indexing, dashboards, and alerting |

### JSON Output <FeatureChip variant="oss" />

In the open-source PolicyEngine, AccessRecords are emitted as JSON to stdout:

```json
{
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "env": {
      "service": "api-gateway",
      "pod": "api-gw-7d9f8b6c4-x2m9k"
    }
  },
  "principal": {
    "subject": "alice@example.com",
    "realm": "employees"
  },
  "operation": "api:documents:read",
  "resource": "mrn:app:document:12345",
  "decision": "GRANT",
  "references": [
    {
      "id": "mrn:iam:policy:require-auth",
      "fingerprint": "a3f2b8c1...",
      "decision": "GRANT",
      "phase": "OPERATION",
      "reason_code": "POLICY_OUTCOME"
    },
    {
      "id": "mrn:iam:role:editor",
      "fingerprint": "d4e5f6a7...",
      "decision": "GRANT",
      "phase": "IDENTITY",
      "reason_code": "POLICY_OUTCOME"
    }
  ],
  "porc": "{...}"
}
```

You can pipe this output to your logging infrastructure, message queue, or analysis tools.

### ElasticSearch Integration <FeatureChip variant="premium" />

The Premium PolicyEngine integrates directly with ElasticSearch, providing:

- **Durable storage**: Historical records with configurable retention
- **Indexed search**: Query by principal, resource, decision, time range, and more
- **Built-in analytics**: Pre-configured dashboards for access patterns
- **Alerting**: Configure alerts for anomalous patterns

## Use Cases

### Compliance Reporting

AccessRecords provide the evidence trail required for compliance audits:

- Demonstrate that access controls are enforced
- Show who accessed what resources and when
- Prove that denied access attempts were properly blocked

### Debugging Access Issues

When users report access problems, AccessRecords reveal exactly what happened:

```bash
# Find recent denials for a specific user (OSS example)
mpe serve ... 2>&1 | jq 'select(.principal.subject == "alice@example.com" and .decision == "DENY")'
```

The detailed policy references show which policy caused the denial and why.

### Anomaly Detection

Build alerting on unusual patterns:

- Spike in denials from a particular source
- Access attempts outside normal hours
- Unusual resource access patterns

### Policy Replay

Because AccessRecords include the complete PORC, you can replay decisions against different policy versions:

1. Capture AccessRecords from production
2. Load a candidate policy version
3. Replay the PORCs and compare decisions
4. Identify any changes in behavior before deploying

This enables safe policy updates by understanding the impact before deployment.

### Analytics

Aggregate AccessRecords to understand your access patterns:

- Most frequently accessed resources
- Policies with the highest denial rates
- Principal activity distributions
- Phase-specific decision patterns

## Best Practices

### Include Environment Context

Use the `audit.env` configuration option to capture deployment context in every AccessRecord. Configure it in your `mpe-config.yaml`:

```yaml
audit:
  env:
    service: SERVICE_NAME
    environment: DEPLOYMENT_ENV
    region: AWS_REGION
    pod: HOSTNAME
```

Each entry maps a key name (that will appear in the AccessRecord) to an environment variable name. The environment variable values are read once at PolicyEngine startup.

For example, with the above configuration and these environment variables set:
- `SERVICE_NAME=api-gateway`
- `DEPLOYMENT_ENV=production`
- `AWS_REGION=us-east-1`
- `HOSTNAME=api-gw-7d9f8b6c4-x2m9k`

Every AccessRecord will include:

```json
{
  "metadata": {
    "env": {
      "service": "api-gateway",
      "environment": "production",
      "region": "us-east-1",
      "pod": "api-gw-7d9f8b6c4-x2m9k"
    }
  }
}
```

This makes it easier to correlate decisions with specific deployments, pods, or regions.

See the [Configuration Reference](/reference/configuration#audit-environment-configuration) for complete details.

### Retain Appropriately

Balance storage costs with compliance and debugging needs:

- **Development**: Short retention (days) for debugging
- **Production**: Longer retention based on compliance requirements
- **Security-sensitive**: Consider extended retention for forensics

### Monitor Decision Rates

Track the ratio of GRANT to DENY decisions. Sudden changes may indicate:

- Policy misconfiguration
- Application bugs sending malformed requests
- Security incidents

## Schema Reference

For the complete AccessRecord schema including all fields, types, and enumeration values, see the [AccessRecord Schema Reference](/reference/access-record).

## Related Concepts

- **[PORC](/concepts/porc)**: The input format captured in AccessRecords
- **[Policy Conjunction](/concepts/policy-conjunction)**: The phases recorded in AccessRecords
- **[Policies](/concepts/policies)**: The policies referenced in AccessRecords