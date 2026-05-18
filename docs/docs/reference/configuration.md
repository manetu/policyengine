---
sidebar_position: 3
---

# Configuration Reference

Environment variables and configuration options for the Manetu PolicyEngine.

## Environment Variables

### CLI Environment Variables

| Variable            | Description                        | Default           |
|---------------------|------------------------------------|-------------------|
| `MPE_CLI_OPA_FLAGS` | Additional OPA flags for lint/test | `--v0-compatible` |

### Logging Variables

| Variable                | Description                                      | Default   |
|-------------------------|--------------------------------------------------|-----------|
| `MPE_LOG_LEVEL`         | Logging level (`debug`, `info`, `warn`, `error`) | `info`    |
| `MPE_LOG_FORMATTER`     | Log format (`json` or `text`)                    | `json`    |
| `MPE_LOG_REPORT_CALLER` | Include caller info in logs                      | (not set) |

### PolicyEngine Variables

| Variable              | Description              | Default           |
|-----------------------|--------------------------|-------------------|
| `MPE_CONFIG_PATH`     | Path to config directory | `.`               |
| `MPE_CONFIG_FILENAME` | Config file name         | `mpe-config.yaml` |
| `MPE_AUXDATA_PATH`    | Directory containing auxiliary data files | (not set) |

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
    - name: service
      type: env
      value: SERVICE_NAME
    - name: region
      type: string
      value: us-east-1
    - name: pod
      type: env
      value: HOSTNAME
```

### Configuration Options

| Option               | Type    | Description                                                                    |
|----------------------|---------|--------------------------------------------------------------------------------|
| `bundles.includeall` | boolean | Include all evaluated bundles in audit records                                 |
| `opa.unsafebuiltins` | string  | Comma-separated list of unsafe OPA built-ins to exclude from policy evaluation |
| `audit.env`          | list    | List of typed entries for AccessRecord metadata (supports env, string, k8s-label, k8s-annot) |
| `audit.k8s.podinfo`  | string  | Path to Kubernetes Downward API podinfo directory (default: `/etc/podinfo`)                   |

### Audit Environment Configuration

The `audit.env` option allows you to include deployment context in every AccessRecord's `metadata.env` field. This is valuable for correlating decisions with specific deployments, pods, or regions.

**Configuration Format:**

Each entry in the `audit.env` list has three fields:

| Field   | Description                                          |
|---------|------------------------------------------------------|
| `name`  | The key that will appear in the AccessRecord metadata |
| `type`  | How to resolve the value (see table below)           |
| `value` | Interpreted according to the type                    |

**Supported Types:**

| Type         | Description                                                    |
|--------------|----------------------------------------------------------------|
| `env`        | Resolve `value` as an environment variable name                |
| `string`     | Use `value` as a literal string                                |
| `k8s-label`  | Look up `value` in Kubernetes pod labels (via Downward API)    |
| `k8s-annot`  | Look up `value` in Kubernetes pod annotations (via Downward API) |

**Example:**

```yaml
audit:
  env:
    - name: service
      type: env
      value: MY_SERVICE_NAME
    - name: environment
      type: string
      value: production
    - name: region
      type: env
      value: AWS_REGION
    - name: pod
      type: env
      value: HOSTNAME
```

If the environment variables are set as:
- `MY_SERVICE_NAME=api-gateway`
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

**Kubernetes Downward API:**

To use `k8s-label` or `k8s-annot` types, configure a Downward API volume mount in your pod spec:

```yaml
volumes:
  - name: podinfo
    downwardAPI:
      items:
        - path: "labels"
          fieldRef:
            fieldPath: metadata.labels
        - path: "annotations"
          fieldRef:
            fieldPath: metadata.annotations
volumeMounts:
  - name: podinfo
    mountPath: /etc/podinfo
```

Then reference labels or annotations in your config:

```yaml
audit:
  env:
    - name: app
      type: k8s-label
      value: app.kubernetes.io/name
    - name: revision
      type: k8s-annot
      value: deployment.kubernetes.io/revision
```

By default, the PolicyEngine reads Downward API files from `/etc/podinfo`. If your volume is mounted at a different path, configure it with `audit.k8s.podinfo`:

```yaml
audit:
  k8s:
    podinfo: /custom/path/podinfo
```

Or via environment variable: `MPE_AUDIT_K8S_PODINFO=/custom/path/podinfo`

**Notes:**
- Values are resolved once at PolicyEngine startup and cached for performance
- If an environment variable is not set, the value will be an empty string
- If Kubernetes Downward API files are not available, `k8s-label` and `k8s-annot` entries resolve to empty strings
- Entries with unknown types are skipped with a warning
- Changes to values after startup will not be reflected until the PolicyEngine is restarted

## Auxiliary Data

Auxiliary data (auxdata) lets you inject environment-specific key/value pairs into mapper input. When `MPE_AUXDATA_PATH` points to a directory, each file in that directory becomes a key (filename) with its content as the value. These are merged into the mapper input under `input.auxdata.*`.

In Kubernetes, this directory is typically a mounted ConfigMap. The helm chart handles this automatically when `sidecar.auxdata` is configured.

For the CLI, use the `--auxdata` flag:

```bash
mpe serve -b domain.yml --auxdata /path/to/auxdata/dir
mpe test mapper -b domain.yml -i input.json --auxdata /path/to/auxdata/dir
```

Mapper Rego code can then reference values like `input.auxdata.region`, `input.auxdata.tier`, etc.

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
export MPE_LOG_FORMATTER=text
mpe serve -b domain.yml
```

## Production Configuration

### Recommended Settings

```bash
# Production logging
export MPE_LOG_LEVEL=.:info
export MPE_LOG_FORMATTER=json

# Disable unsafe built-ins
# (don't set opa.unsafebuiltins in config)

# Run server
mpe serve -b domain.yml --port 9000
```

### Docker Configuration

```dockerfile
ENV MPE_LOG_LEVEL=.:info
ENV MPE_LOG_FORMATTER=json
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mpe-config
data:
  MPE_LOG_LEVEL: "info"
  MPE_LOG_FORMATTER: "json"
```
