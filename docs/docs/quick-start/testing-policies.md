---
sidebar_position: 3
---

# Testing Policies

The `mpe test` command provides several ways to test your policies during development.

## Test Commands Overview

| Command | Description |
|---------|-------------|
| `mpe test decision` | Test policy decisions with [PORC](/concepts/porc) input |
| `mpe test mapper` | Test [mapper](/concepts/mappers) transformations |
| `mpe test envoy` | Test full Envoy-to-decision pipeline |

## Understanding Test Output

Before diving into the commands, it helps to understand what each command outputs:

### Decision and Envoy Output: AccessRecord

The `mpe test decision` and `mpe test envoy` commands output an **AccessRecord**—a JSON document that captures everything about the policy evaluation. The most important field is `decision`, which will be either `"GRANT"` or `"DENY"`.

```json
{
  "decision": "GRANT",
  "principal": { "subject": "user123", "realm": "" },
  "operation": "api:resource:read",
  "resource": "mrn:app:resource:123",
  "references": [ ... ],
  "porc": "{ ... }"
}
```

Key fields you'll see:

| Field | Description |
|-------|-------------|
| `decision` | The final outcome: `"GRANT"` or `"DENY"` |
| `principal` | Who made the request (extracted from PORC) |
| `operation` | What action was attempted |
| `resource` | What resource was accessed |
| `references` | Details about each policy evaluated (useful for debugging) |

To quickly extract just the decision, pipe the output through `jq`:

```bash
mpe test decision -b my-domain.yml -i input.json | jq .decision
# Output: "GRANT" or "DENY"
```

For a deeper understanding of AccessRecords and how they support auditing and debugging, see [Audit & Access Records](/concepts/audit).

### Mapper Output: PORC Expression

The `mpe test mapper` command outputs a **[PORC expression](/concepts/porc)**—the standardized format that policies evaluate. This shows how your mapper transforms external input (like an Envoy request) into the Principal, Operation, Resource, and Context structure:

```json
{
  "principal": { "sub": "user@example.com", "mroles": [...] },
  "operation": "my-service:http:get",
  "resource": { "id": "mrn:http:my-service/api/users/123", ... },
  "context": { ... }
}
```

This is useful for verifying that your mapper correctly extracts identity information and constructs the operation and resource fields.

## Testing Policy Decisions

### Basic Decision Test

Test a policy with a [PORC expression](/concepts/porc):

```bash
# Create a PORC input file
cat > input.json << 'EOF'
{
  "principal": {
    "sub": "user123",
    "mroles": ["mrn:iam:role:admin"]
  },
  "operation": "api:resource:read",
  "resource": {
    "id": "mrn:app:resource:123",
    "group": "mrn:iam:resource-group:default"
  },
  "context": {}
}
EOF

# Test the decision
mpe test decision -b my-domain.yml -i input.json
```

### Testing Different Scenarios

**Authenticated User with Admin Role:**

```json
{
  "principal": {
    "sub": "admin-user",
    "mroles": ["mrn:iam:role:admin"],
    "mgroups": ["mrn:iam:group:admins"]
  },
  "operation": "api:users:delete",
  "resource": {
    "id": "mrn:app:user:456",
    "group": "mrn:iam:resource-group:default"
  }
}
```

**Unauthenticated Request (should be denied):**

```json
{
  "principal": {},
  "operation": "api:data:read",
  "resource": {
    "id": "mrn:app:data:secret",
    "group": "mrn:iam:resource-group:default"
  }
}
```

**Resource with Classification:**

```json
{
  "principal": {
    "sub": "user123",
    "mroles": ["mrn:iam:role:analyst"],
    "mclearance": "HIGH"
  },
  "operation": "vault:secret:read",
  "resource": {
    "id": "mrn:vault:secret:123",
    "group": "mrn:iam:resource-group:classified",
    "classification": "MODERATE",
    "owner": "user456"
  }
}
```

## Testing Mappers

[Mappers](/concepts/mappers) transform external inputs into PORC expressions. Test them separately:

```bash
# Create an Envoy-style input
cat > envoy-input.json << 'EOF'
{
  "request": {
    "http": {
      "method": "GET",
      "path": "/api/users/123",
      "headers": {
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      }
    }
  },
  "destination": {
    "principal": "spiffe://cluster.local/ns/default/sa/my-service"
  }
}
EOF

# Test the mapper
mpe test mapper -b my-domain.yml -i envoy-input.json
```

The output is a [PORC expression](/concepts/porc) showing how the mapper transformed the input. You can inspect specific fields with `jq`:

```bash
# Check what operation was generated
mpe test mapper -b my-domain.yml -i envoy-input.json | jq .operation

# Verify the principal was extracted correctly
mpe test mapper -b my-domain.yml -i envoy-input.json | jq .principal
```

## Testing Full Pipeline

Test the complete Envoy input to decision pipeline:

```bash
mpe test envoy -b my-domain.yml -i envoy-input.json
```

This runs both stages and outputs an AccessRecord (same format as `mpe test decision`):

1. **Mapper**: Transform Envoy input → PORC
2. **Decision**: Evaluate PORC against policies → AccessRecord

```bash
# Get the final decision
mpe test envoy -b my-domain.yml -i envoy-input.json | jq .decision
```

## Using Multiple Bundles

You can load multiple PolicyDomain bundles:

```bash
mpe test decision \
  -b base-policies.yml \
  -b app-specific.yml \
  -i input.json
```

Policies from all bundles are available for evaluation.

## Enabling Trace Output

For debugging, enable OPA trace output:

```bash
mpe --trace test decision -b my-domain.yml -i input.json
```

This shows detailed evaluation steps.

## Testing with stdin

Read input from stdin:

```bash
echo '{"principal": {"sub": "test", "mroles": ["mrn:iam:role:user"]}, "operation": "test:op", "resource": {"id": "test", "group": "mrn:iam:resource-group:default"}}' | \
  mpe test decision -b my-domain.yml -i -
```

:::tip[stdin is the default]
You may omit '-i -' when you wish to use stdin-based input because it is the default
:::

## Common Test Patterns

### Test JWT Validation

```json
{
  "principal": {},
  "operation": "api:secure:read",
  "resource": {
    "id": "mrn:app:data:secret",
    "group": "mrn:iam:resource-group:default"
  }
}
```

Expected: DENY (no principal)

### Test Role-Based Access

```json
{
  "principal": {
    "sub": "user1",
    "mroles": ["mrn:iam:role:viewer"]
  },
  "operation": "api:data:write",
  "resource": {
    "id": "mrn:app:data:123",
    "group": "mrn:iam:resource-group:default"
  }
}
```

Expected: DENY (viewer role typically lacks write permissions)

### Test Resource Ownership

```json
{
  "principal": {
    "sub": "user123",
    "mroles": ["mrn:iam:role:user"]
  },
  "operation": "api:item:delete",
  "resource": {
    "id": "mrn:app:item:456",
    "owner": "user123",
    "group": "mrn:iam:resource-group:owner-access"
  }
}
```

Expected: GRANT (owner access, assuming role and resource-group policies permit owner operations)

## Best Practices

1. **Create a test suite**: Maintain JSON files for common scenarios
2. **Test edge cases**: Empty principals, missing fields, invalid data
3. **Test both GRANT and DENY**: Verify policies correctly reject unauthorized access
4. **Use trace for debugging**: When tests fail unexpectedly, enable `--trace`
5. **Test libraries independently**: Verify library functions work as expected

## Next Steps

- [CLI Reference](/reference/cli/test) - Complete test command reference with all options
- [PORC Expressions](/concepts/porc) - Understand the authorization request format
- [Audit & Access Records](/concepts/audit) - Learn how AccessRecords support debugging and compliance
- [AccessRecord Schema](/reference/access-record) - Complete field reference for test output
