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
```

### Configuration Options

| Option | Type | Description                                                                    |
|--------|------|--------------------------------------------------------------------------------|
| `bundles.includeall` | boolean | Include all evaluated bundles in audit records                                 |
| `opa.unsafebuiltins` | string | Comma-separated list of unsafe OPA built-ins to exclude from policy evaluation |

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
