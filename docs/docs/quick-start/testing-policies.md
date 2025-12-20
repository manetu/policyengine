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
    "id": "mrn:app:data:secret"
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

The output will show the generated PORC expression.

## Testing Full Pipeline

Test the complete Envoy input to decision pipeline:

```bash
mpe test envoy -b my-domain.yml -i envoy-input.json
```

This runs:
1. Mapper: Transform Envoy input → PORC
2. Decision: Evaluate PORC against policies

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

## Common Test Patterns

### Test JWT Validation

```json
{
  "principal": {},
  "operation": "api:secure:read"
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
  "resource": {
    "id": "mrn:app:item:456",
    "owner": "user123",
    "group": "mrn:iam:resource-group:owner-access"
  },
  "operation": "api:item:delete"
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

- [CLI Reference](/reference/cli/test) - Complete test command reference
- [PORC Expressions](/concepts/porc) - Understand PORC expressions
