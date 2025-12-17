---
sidebar_position: 3
---

# Configuration Reference

Environment variables and configuration options for the Manetu PolicyEngine.

## Environment Variables

### CLI Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MPE_CLI_OPA_FLAGS` | Additional OPA flags for lint/test | `--v0-compatible` |

### Logging Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MPE_LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`) | `info` |
| `LOG_FORMATTER` | Log format (`json` or `text`) | `json` |
| `LOG_REPORT_CALLER` | Include caller info in logs | (not set) |

### PolicyEngine Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MPE_CONFIG_PATH` | Path to config directory | `.` |
| `MPE_CONFIG_FILENAME` | Config file name | `mpe-config.yaml` |

## Configuration File

The optional `mpe-config.yaml` file provides additional configuration:

```yaml
# Include all bundle references in audit logs
bundles:
  includeall: true

# Unsafe built-ins to disallow from policy decisions.
opa:
  unsafebuiltins: "http.send"

# Include environment context in AccessRecord metadata
audit:
  env:
    service: SERVICE_NAME
    region: AWS_REGION
    pod: HOSTNAME
```

### Configuration Options

| Option | Type | Description                                                                    |
|--------|------|--------------------------------------------------------------------------------|
| `bundles.includeall` | boolean | Include all evaluated bundles in audit records                                 |
| `opa.unsafebuiltins` | string | Comma-separated list of unsafe OPA built-ins to exclude from policy evaluation |
| `audit.env` | map | Map of key names to environment variable names for AccessRecord metadata |

### Audit Environment Configuration

The `audit.env` option allows you to include deployment context in every AccessRecord's `metadata.env` field. This is valuable for correlating decisions with specific deployments, pods, or regions.

**Configuration Format:**

```yaml
audit:
  env:
    <key-name>: <ENVIRONMENT_VARIABLE_NAME>
```

- **key-name**: The name that will appear in the AccessRecord's `metadata.env` field
- **ENVIRONMENT_VARIABLE_NAME**: The environment variable to read the value from

**Example:**

```yaml
audit:
  env:
    service: MY_SERVICE_NAME
    environment: DEPLOYMENT_ENV
    region: AWS_REGION
    pod: HOSTNAME
```

If the environment variables are set as:
- `MY_SERVICE_NAME=api-gateway`
- `DEPLOYMENT_ENV=production`
- `AWS_REGION=us-east-1`
- `HOSTNAME=api-gw-7d9f8b6c4-x2m9k`

The resulting AccessRecord metadata will include:

```json
{
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "env": {
      "service": "api-gateway",
      "environment": "production",
      "region": "us-east-1",
      "pod": "api-gw-7d9f8b6c4-x2m9k"
    }
  }
}
```

**Notes:**
- Environment variables are resolved once at PolicyEngine startup and cached for performance
- If an environment variable is not set, the value will be an empty string
- Changes to environment variables after startup will not be reflected until the PolicyEngine is restarted

## OPA Flags

Default OPA flags used by the CLI: `--v0-compatible`

Override via:
- Command line: `--opa-flags "--strict --v1-compatible"`
- Environment: `MPE_CLI_OPA_FLAGS="--strict"`
- Disable: `--no-opa-flags`

### Common OPA Flags

| Flag | Description |
|------|-------------|
| `--v0-compatible` | Enable OPA v0 compatibility |
| `--v1-compatible` | Enable OPA v1 compatibility |
| `--strict` | Enable strict mode |

## Logging Configuration

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Verbose debugging information |
| `info` | General operational information |
| `warn` | Warning messages |
| `error` | Error messages only |

### Example

```bash
# Enable debug logging with text format
export MPE_LOG_LEVEL=.:debug
export LOG_FORMATTER=text
mpe serve -b domain.yml
```

## Production Configuration

### Recommended Settings

```bash
# Production logging
export MPE_LOG_LEVEL=.:info
export LOG_FORMATTER=json

# Disable unsafe built-ins
# (don't set unsafe.builtins in config)

# Run server
mpe serve -b domain.yml --port 9000
```

### Docker Configuration

```dockerfile
ENV MPE_LOG_LEVEL=.:info
ENV LOG_FORMATTER=json
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mpe-config
data:
  MPE_LOG_LEVEL: "info"
  LOG_FORMATTER: "json"
```
