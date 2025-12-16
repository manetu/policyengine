---
sidebar_position: 4
---

# mpe test

Test policy decisions and mappers with various inputs.

## Synopsis

```bash
mpe test decision --bundle <file> --input <file>
mpe test mapper --bundle <file> --input <file>
mpe test envoy --bundle <file> --input <file>
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `decision` | Test policy decisions with PORC input |
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

## Testing Scenarios

### Test Authentication

```json
{
  "principal": {},
  "operation": "api:secure:read",
  "resource": {"id": "test"}
}
```

Expected: DENY (no principal)

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

Expected: DENY (viewer can't write)

### Test Owner Access

```json
{
  "principal": {"sub": "owner123"},
  "operation": "api:resource:delete",
  "resource": {
    "id": "mrn:app:item:456",
    "owner": "owner123"
  }
}
```

Expected: GRANT (owner access)

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Command executed successfully |
| 1 | Error (invalid input, missing files, etc.) |

Note: Exit code 0 doesn't mean GRANT - check the output for the decision.
