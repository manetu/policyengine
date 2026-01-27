---
sidebar_position: 4
---

# mpe test

Test policy decisions and mappers with various inputs.

## Synopsis

```bash
mpe test decision --bundle <file> --input <file>
mpe test decisions --bundle <file> --input <file>
mpe test mapper --bundle <file> --input <file>
mpe test envoy --bundle <file> --input <file>
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `decision` | Test a single policy decision with PORC input |
| `decisions` | Run a suite of policy decision tests from a YAML file |
| `mapper` | Test mapper transformations |
| `envoy` | Test full Envoy-to-decision pipeline |

## test decision

Evaluate a policy decision based on a PORC expression.

### Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--bundle` | `-b` | PolicyDomain bundle file(s) |
| `--input` | `-i` | PORC input file or `-` for stdin |
| `--test` | | Specific test to run |

### Example

```bash
# Using a file
mpe test decision -b my-domain.yml -i porc-input.json

# Using stdin
echo '{"principal":{"sub":"user1"},"operation":"api:test","resource":{"id":"test"}}' | \
  mpe test decision -b my-domain.yml -i -

# Multiple bundles
mpe test decision -b base.yml -b override.yml -i input.json
```

### Input Format

```json
{
  "principal": {
    "sub": "user@example.com",
    "mroles": ["mrn:iam:role:admin"]
  },
  "operation": "api:users:read",
  "resource": {
    "id": "mrn:app:users:123",
    "group": "mrn:iam:resource-group:default"
  },
  "context": {}
}
```

### Output

The command outputs a JSON-encoded **Access Record** (defined in `protos/manetu/policyengine/events/v1/message.proto`). This record contains detailed information about the decision process.

**Key fields in the Access Record:**

| Field | Description |
|-------|-------------|
| `decision` | The final outcome: `"GRANT"`, `"DENY"`, or `"UNSPECIFIED"` |
| `principal` | The authenticated principal (subject and realm) |
| `operation` | The operation from the PORC expression |
| `resource` | The resource MRN from the PORC expression |
| `references` | List of policy bundles consulted, each with its own decision and phase |
| `porc` | The fully realized PORC JSON |
| `system_override` | Whether an operation phase (Phase 1) decision bypass was applied |
| `grant_reason` / `deny_reason` | Reason for any bypass (e.g., `PUBLIC`, `JWT_REQUIRED`) |

**Using jq to extract specific fields:**

```bash
# Get just the decision (returns "GRANT", "DENY", or "UNSPECIFIED")
mpe test decision -b my-domain.yml -i input.json | jq .decision

# View all policy references consulted
mpe test decision -b my-domain.yml -i input.json | jq .references

# Check for any bypass reasons
mpe test decision -b my-domain.yml -i input.json | jq '{grant_reason, deny_reason, system_override}'
```

## test decisions

Run a suite of policy decision tests from a YAML file. This command is designed for automated testing and CI/CD pipelines, allowing you to define multiple test cases with expected outcomes in a single file.

### Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--bundle` | `-b` | PolicyDomain bundle file(s) |
| `--input` | `-i` | Test suite YAML file (required) |
| `--test` | | Run only tests matching this glob pattern (can be repeated) |

### Example

```bash
# Run all tests in a suite
mpe test decisions -b my-domain.yml -i tests.yaml

# Run a specific test for debugging
mpe test decisions -b my-domain.yml -i tests.yaml --test my-failing-test

# Run tests matching a pattern
mpe test decisions -b my-domain.yml -i tests.yaml --test "admin-*"

# Run multiple patterns
mpe test decisions -b my-domain.yml -i tests.yaml --test "admin-*" --test "viewer-*"
```

### Input Format

The test suite is a YAML file containing a list of test cases. Each test case specifies:
- `name`: A unique identifier for the test
- `description`: What the test verifies
- `porc`: The PORC expression to evaluate
- `result.allow`: The expected outcome (`true` for GRANT, `false` for DENY)

```yaml
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
    description: Unauthenticated users cannot access protected resources
    porc:
      principal: {}
      operation: api:protected:read
      resource:
        id: mrn:app:resource:1
        group: mrn:iam:resource-group:default
    result:
      allow: false
```

### Output

The command outputs the result of each test, followed by a summary:

```
admin-can-read: PASS
viewer-cannot-delete: PASS
unauthenticated-denied: PASS

3/3 tests passed
```

On failure, the output shows what was expected vs. what was received:

```
admin-can-read: PASS
viewer-cannot-delete: FAIL (expected allow=false, got allow=true)

1/2 tests passed
```

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | All tests passed |
| 1 | One or more tests failed, or an error occurred |

:::tip CI/CD Integration
The `test decisions` command is designed for CI/CD pipelines. The exit code directly reflects test outcomes, making integration straightforward:

```bash
# In your CI pipeline
mpe test decisions -b domain.yml -i tests.yaml
# Exit code 0 = all tests passed
# Exit code 1 = at least one test failed
```
:::

### Debugging Failed Tests

When investigating why a test is failing, use the `--trace` flag to see the full AccessRecord and OPA trace output:

```bash
mpe --trace test decisions -b domain.yml -i tests.yaml --test failing-test-name
```

This outputs:
- **OPA trace**: Shows rule evaluation order, variable bindings, and decision path
- **AccessRecord**: Shows which policies were evaluated, their decisions, and phase information

The trace output goes to stderr, so it won't interfere with test result parsing.

## test mapper

Test mapper transformation of external input to PORC.

### Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--bundle` | `-b` | PolicyDomain bundle file(s) |
| `--input` | `-i` | External input file or `-` for stdin |
| `--name` | `-n` | Domain name when using multiple bundles |
| `--opa-flags` | | Additional OPA flags |
| `--no-opa-flags` | | Disable OPA flags |

### Example

```bash
mpe test mapper -b my-domain.yml -i envoy-input.json
```

### Input Format (Envoy-style)

```json
{
  "request": {
    "http": {
      "method": "GET",
      "path": "/api/users/123",
      "headers": {
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9..."
      }
    }
  },
  "destination": {
    "principal": "spiffe://cluster.local/ns/default/sa/api-server"
  }
}
```

### Output

The command outputs a **JSON-encoded PORC expression** showing how the mapper transformed the external input. This is useful for debugging mappers and verifying that external requests are correctly translated to PORC.

```json
{
  "principal": {
    "sub": "user@example.com"
  },
  "operation": "api-server:http:get",
  "resource": {
    "id": "http://api-server/api/users/123",
    "group": "mrn:iam:resource-group:default"
  },
  "context": { ... }
}
```

**Using jq to inspect specific fields:**

```bash
# Extract just the principal
mpe test mapper -b my-domain.yml -i envoy-input.json | jq .principal

# Check the generated operation
mpe test mapper -b my-domain.yml -i envoy-input.json | jq .operation

# View resource details
mpe test mapper -b my-domain.yml -i envoy-input.json | jq .resource
```

## test envoy

Execute the complete pipeline: Envoy input → mapper → PORC → decision.

### Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--bundle` | `-b` | PolicyDomain bundle file(s) |
| `--input` | `-i` | Envoy input file or `-` for stdin |
| `--name` | `-n` | Domain name when using multiple bundles |
| `--opa-flags` | | Additional OPA flags |
| `--no-opa-flags` | | Disable OPA flags |

### Example

```bash
mpe test envoy -b my-domain.yml -i envoy-request.json
```

### Output

Like `mpe test decision`, this command outputs a JSON-encoded **Access Record** containing the full decision details. See the [test decision output section](#output) for the complete field reference.

**Using jq to extract specific fields:**

```bash
# Get just the decision
mpe test envoy -b my-domain.yml -i envoy-request.json | jq .decision

# View the PORC that was generated from the Envoy input
mpe test envoy -b my-domain.yml -i envoy-request.json | jq .porc

# See which policy bundles were evaluated
mpe test envoy -b my-domain.yml -i envoy-request.json | jq .references
```

## Trace Output

Enable detailed OPA trace logging:

```bash
mpe --trace test decision -b my-domain.yml -i input.json
```

This shows:
- Rule evaluation order
- Data lookups
- Variable bindings
- Decision path

### Filtering Trace Output

Use `--trace-filter` to limit trace output to specific policies:

```bash
# Trace only policies matching the pattern
mpe --trace --trace-filter "mrn:iam:policy:my-policy" test decision -b my-domain.yml -i input.json

# Multiple filters (matches any)
mpe --trace --trace-filter "pattern1" --trace-filter "pattern2" test decision -b my-domain.yml -i input.json
```

Each filter is a regex pattern matched against the policy MRN.

For a complete guide to interpreting trace output, see [Debugging Policies](/guides/debugging-policies).

## Testing Scenarios

### Test Authentication

```json
{
  "principal": {},
  "operation": "api:secure:read",
  "resource": {"id": "test", "group": "mrn:iam:resource-group:default"}
}
```

Expected: <DecisionChip decision="deny" /> (no principal — fails at operation phase before identity evaluation)

### Test Role Access

```json
{
  "principal": {
    "sub": "user1",
    "mroles": ["mrn:iam:role:viewer"]
  },
  "operation": "api:data:write",
  "resource": {"id": "data", "group": "mrn:iam:resource-group:default"}
}
```

Expected: <DecisionChip decision="deny" /> (viewer can't write)

### Test Owner Access

```json
{
  "principal": {"sub": "owner123"},
  "operation": "api:resource:delete",
  "resource": {
    "id": "mrn:app:item:456",
    "group": "mrn:iam:resource-group:default",
    "owner": "owner123"
  }
}
```

Expected: <DecisionChip decision="grant" /> (owner access)

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Command executed successfully |
| 1 | Error (invalid input, missing files, etc.) |

Note: Exit code 0 doesn't mean GRANT—check the output for the decision.

:::tip CI/CD Integration with jq halt_error
For CI pipelines that need to fail based on the decision outcome, use `jq`'s [`halt_error`](https://jqlang.github.io/jq/manual/#halt_error) function:

```bash
# Fail CI if access is denied
mpe test decision -b domain.yml -i input.json | \
  jq 'if .decision == "DENY" then "Access denied" | halt_error(1) else . end'

# Fail CI if access is granted (for negative test cases)
mpe test decision -b domain.yml -i input.json | \
  jq 'if .decision == "GRANT" then "Expected DENY" | halt_error(1) else . end'
```

This pipes the AccessRecord through `jq`, which exits with code 1 and prints the error message if the condition is met.
:::
