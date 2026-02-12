---
sidebar_position: 1
---

# CLI Reference

The `mpe` CLI provides tools for developing, testing, and serving policies.

## Installation

See [Installing the CLI](/getting-started/installation#installing-the-cli) within the Getting Started guide.

## Global Options

```
--trace, -t    Enable OPA trace logging output (default: false)
--help, -h     Show help
```

## Commands

| Command | Description |
|---------|-------------|
| <IconText icon="build">[`build`](/reference/cli/build)</IconText> | Build PolicyDomain from PolicyDomainReference |
| <IconText icon="lint">[`lint`](/reference/cli/lint)</IconText> | Validate YAML and lint Rego code |
| <IconText icon="test">[`test`](/reference/cli/test)</IconText> | Test policy decisions and mappers |
| <IconText icon="serve">[`serve`](/reference/cli/serve)</IconText> | Run a policy decision point server |
| <IconText icon="version">[`version`](/reference/cli/version)</IconText> | Print the version of mpe |

## Quick Examples

### Lint a PolicyDomain

```bash
mpe lint -f my-domain.yml
```

### Build from Reference

```bash
mpe build -f my-domain-ref.yml -o my-domain.yml
```

### Test a Decision

```bash
mpe test decision -b my-domain.yml -i input.json
```

### Run a Server

```bash
mpe serve -b my-domain.yml --port 9000
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MPE_CLI_OPA_FLAGS` | Additional OPA flags | `--v0-compatible` |
| `MPE_LOG_LEVEL` | Logging level | `info` |
| `MPE_LOG_FORMATTER` | Log format (`json` or `text`) | `json` |

## Advanced Debugging

The `mpe` CLI includes powerful debugging capabilities for policy development and troubleshooting.

### Trace Mode

Enable detailed policy evaluation tracing with the `--trace` flag:

```bash
mpe --trace test decision -b my-domain.yml -i input.json
```

Trace output shows:
- **Rule evaluation order**: See which rules are evaluated and in what sequence
- **Data lookups**: Track how data is accessed during evaluation
- **Variable bindings**: Understand how variables are assigned
- **Decision path**: Follow the exact path through your policy logic

This is invaluable for debugging complex policies or understanding why a particular decision was made.

### Testing Workflow

The CLI supports a complete policy development lifecycle:

```bash
# 1. Validate syntax and structure
mpe lint -f domain.yaml

# 1b. Run Regal linting for Rego style and best practices
mpe lint -f domain.yaml --regal

# 2. Test individual decisions
mpe test decision -b domain.yaml -i test-input.json

# 3. Test mapper transformations
mpe test mapper -b domain.yaml -i envoy-input.json

# 4. Test full Envoy pipeline
mpe test envoy -b domain.yaml -i envoy-request.json

# 5. Run local server for integration testing
mpe serve -b domain.yaml --port 9000
```

### Output Processing

All test commands output JSON, making them easy to process with tools like `jq`:

```bash
# Extract just the decision
mpe test decision -b domain.yaml -i input.json | jq .decision

# View all policy references evaluated
mpe test decision -b domain.yaml -i input.json | jq .references

# Check for bypass reasons
mpe test decision -b domain.yaml -i input.json | jq '{grant_reason, deny_reason}'
```

### CI/CD Integration

The CLI is designed for automation:

```bash
# Exit code indicates success/failure (not GRANT/DENY)
mpe lint -f domain.yaml && echo "Lint passed"
```

:::tip Using jq halt_error for CI assertions
The `mpe test` commands always exit 0 on successful execution, regardless of whether access was granted or denied. Use `jq`'s [`halt_error`](https://jqlang.github.io/jq/manual/#halt_error) to fail CI pipelines based on the decision:

```bash
# Fail if access is denied
mpe test decision -b domain.yaml -i input.json | \
  jq 'if .decision == "DENY" then "Access denied" | halt_error(1) else . end'

# Fail if access is granted (for negative tests)
mpe test decision -b domain.yaml -i input.json | \
  jq 'if .decision == "GRANT" then "Expected DENY" | halt_error(1) else . end'
```

This is cleaner than shell variable checks and provides clear error messages in CI logs.
:::

:::tip Premium Feature: Advanced Analytics
The **Premium Edition** extends these capabilities with:
- **Decision replay**: Replay historical decisions with full context
- **Visual code coverage**: See which policy paths were evaluated
- **Benchmarking**: Measure policy evaluation performance
- **Audit analysis**: Query and analyze decision patterns over time
:::

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (validation failed, file not found, etc.) |

:::note
Exit code 0 indicates the command executed successfully, not that access was granted. For `mpe test` commands, check the JSON output for the actual decision.
:::
