---
sidebar_position: 2
---

# Testing Policies

This guide covers the full range of testing capabilities provided by the `mpe test` command, helping you verify your policies work correctly during development and before deployment.

## Test Commands Overview

| Command              | Description                                              |
|----------------------|----------------------------------------------------------|
| `mpe test decision`  | Test a single policy decision with [PORC](/concepts/porc) input |
| `mpe test decisions` | Run a suite of tests from a YAML file                    |
| `mpe test mapper`    | Test [mapper](/concepts/mappers) transformations         |
| `mpe test envoy`     | Test full Envoy-to-decision pipeline                     |

## Understanding Test Output

### Decision and Envoy Output: AccessRecord

The `mpe test decision` and `mpe test envoy` commands output an [**AccessRecord**](/concepts/audit#the-accessrecord)—a JSON document that captures everything about the policy evaluation. The most important field is `decision`, which will be either `"GRANT"` or `"DENY"`.

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

| Field        | Description                                                |
|--------------|------------------------------------------------------------|
| `decision`   | The final outcome: `"GRANT"` or `"DENY"`                   |
| `principal`  | Who made the request (extracted from PORC)                 |
| `operation`  | What action was attempted                                  |
| `resource`   | What resource was accessed                                 |
| `references` | Details about each policy evaluated (useful for debugging) |

To quickly extract just the decision, pipe the output through `jq`:

```bash
mpe test decision -b my-domain.yml -i input.json | jq .decision
# Output: "GRANT" or "DENY"
```

For human-readable output during debugging, add the `--pretty-log` flag:

```bash
mpe test decision -b my-domain.yml -i input.json --pretty-log
```

This produces indented JSON with the `porc` field expanded, making it easier to inspect. For a complete guide to interpreting AccessRecords, see [Reading Access Records](/guides/reading-access-records).

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

[Mappers](/concepts/mappers) transform external inputs into PORC expressions. Test them separately to verify the transformation logic:

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

## Running Test Suites

For automated testing and CI/CD pipelines, define multiple test cases in a YAML file and run them with `mpe test decisions`:

```yaml
# tests.yaml
tests:
  - name: admin-can-read
    description: Admin role can perform read operations
    porc:
      principal:
        sub: admin@example.com
        mroles:
          - mrn:iam:role:admin
      operation: api:documents:read
      resource:
        id: mrn:app:document:123
        group: mrn:iam:resource-group:default
    result:
      allow: true

  - name: viewer-cannot-delete
    description: Viewer role cannot delete resources
    porc:
      principal:
        sub: viewer@example.com
        mroles:
          - mrn:iam:role:viewer
      operation: api:documents:delete
      resource:
        id: mrn:app:document:123
        group: mrn:iam:resource-group:default
    result:
      allow: false

  - name: unauthenticated-denied
    description: Requests without a principal are denied
    porc:
      principal: {}
      operation: api:documents:read
      resource:
        id: mrn:app:document:123
        group: mrn:iam:resource-group:default
    result:
      allow: false
```

Run the entire suite:

```bash
mpe test decisions -b my-domain.yml -i tests.yaml
```

Output shows pass/fail status for each test:

```
admin-can-read: PASS
viewer-cannot-delete: PASS
unauthenticated-denied: PASS

3/3 tests passed
```

### Running Specific Tests

Use `--test` to run only tests matching a glob pattern:

```bash
# Run only admin-related tests
mpe test decisions -b my-domain.yml -i tests.yaml --test "admin-*"

# Run multiple patterns
mpe test decisions -b my-domain.yml -i tests.yaml --test "admin-*" --test "viewer-*"
```

### Test Suite Best Practices

1. **Group related tests**: Use naming conventions like `role-admin-*`, `phase-operation-*`
2. **Test both positive and negative cases**: Verify GRANT and DENY scenarios
3. **Include edge cases**: Empty principals, missing fields, boundary conditions
4. **Add descriptions**: Document what each test verifies for future maintainers
5. **Use in CI/CD**: Run test suites on every commit to catch regressions

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

When tests fail unexpectedly, enable OPA trace output to see step-by-step evaluation:

```bash
mpe --trace test decision -b my-domain.yml -i input.json
```

Combine with `--pretty-log` for easier reading:

```bash
mpe --trace --pretty-log test decision -b my-domain.yml -i input.json
```

The trace shows each rule entry, exit, and failure. For a complete guide to interpreting trace output, see [Debugging Policies](/guides/debugging-policies).

## Testing with stdin

Read input from stdin:

```bash
echo '{"principal": {"sub": "test", "mroles": ["mrn:iam:role:user"]}, "operation": "test:op", "resource": {"id": "test", "group": "mrn:iam:resource-group:default"}}' | \
  mpe test decision -b my-domain.yml -i -
```

:::tip[stdin is the default]
You may omit `-i -` when you wish to use stdin-based input because it is the default.
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

Expected: <DecisionChip decision="deny" /> (no principal)

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

Expected: <DecisionChip decision="deny" /> (viewer role typically lacks write permissions)

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

Expected: <DecisionChip decision="grant" /> (owner access, assuming role and resource-group policies permit owner operations)

## Best Practices

1. **Create a test suite**: Maintain JSON files for common scenarios
2. **Test edge cases**: Empty principals, missing fields, invalid data
3. **Test both GRANT and DENY**: Verify policies correctly reject unauthorized access
4. **Use trace for debugging**: When tests fail unexpectedly, enable `--trace` (see [Debugging Policies](/guides/debugging-policies))
5. **Test mappers independently**: Verify mapper transformations before testing the full pipeline
6. **Use `--pretty-log` for debugging**: Human-readable output makes it easier to understand evaluation results

## See Also

- [CLI Reference: mpe test](/reference/cli/test) — Complete command reference with all options
- [Reading Access Records](/guides/reading-access-records) — How to interpret test output
- [Debugging Policies](/guides/debugging-policies) — How to interpret OPA trace output
- [PORC Expressions](/concepts/porc) — Understanding the authorization request format
- [Audit & Access Records](/concepts/audit) — How AccessRecords support debugging and compliance
- [AccessRecord Schema](/reference/access-record) — Complete field reference for test output
