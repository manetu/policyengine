---
sidebar_position: 5
---

# mpe serve

Run a policy decision point server.

## Synopsis

```bash
mpe serve --bundle <file> [--port <port>] [--protocol <protocol>]
```

## Description

The `serve` command starts a gRPC/HTTP server that acts as a Policy Decision Point (PDP). It can serve:

- **Generic protocol**: Direct PORC-based requests over a [Swagger-based](https://swagger.io) HTTP endpoint
- **Envoy protocol**: Envoy [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) compatible requests

## Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--bundle` | `-b` | PolicyDomain bundle file(s) | Required |
| `--port` | | TCP port to serve on | 9000 |
| `--protocol` | `-p` | Protocol: `generic` or `envoy` | generic |
| `--name` | `-n` | Domain name for multiple bundles | |
| `--opa-flags` | | Additional OPA flags | `--v0-compatible` |
| `--no-opa-flags` | | Disable OPA flags | |

## Examples

### Basic Server

```bash
mpe serve -b my-domain.yml
# Server listening on port 9000
```

### Custom Port

```bash
mpe serve -b my-domain.yml --port 8080
```

### Envoy Protocol

```bash
mpe serve -b my-domain.yml -p envoy --port 9001
```

### Multiple Bundles

```bash
mpe serve -b base.yml -b app.yml -n my-app
```

## Generic Protocol

The generic protocol accepts PORC expressions directly:

### Request Format

```json
{
  "principal": {
    "sub": "user@example.com",
    "mroles": ["mrn:iam:role:admin"]
  },
  "operation": "api:users:read",
  "resource": {
    "id": "mrn:app:users"
  },
  "context": {}
}
```

### Response Format

```json
{
  "allow": true
}
```

## Envoy Protocol

The Envoy protocol is compatible with [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter):

### Request Flow

1. Envoy sends ext_authz request
2. Mapper transforms request to PORC
3. Policy evaluation
4. Response returned to Envoy

### Integration with Envoy

```yaml
# Envoy configuration
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service:
      envoy_grpc:
        cluster_name: ext_authz
      timeout: 0.25s
    transport_api_version: V3

clusters:
- name: ext_authz
  type: STRICT_DNS
  lb_policy: ROUND_ROBIN
  http2_protocol_options: {}
  load_assignment:
    cluster_name: ext_authz
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: mpe-server
              port_value: 9001
```

## Health Checks

The server exposes a health endpoint for Kubernetes/load balancer integration.

## Logging

Configure logging via environment variables:

```bash
# Log level
export MPE_LOG_LEVEL=.:debug

# Log format (json or text)
export MPE_LOG_FORMATTER=text

mpe serve -b my-domain.yml
```

## Production Considerations

### Performance

- Use connection pooling from clients
- Deploy multiple replicas for high availability

### Security

- Use TLS for production deployments
- Limit network access to the server
- Validate inputs in mappers

### Monitoring

- Monitor decision latency
- Track allow/deny ratios
- Alert on error rates

## Docker Usage

```dockerfile
FROM golang:1.21-alpine as builder
WORKDIR /app
COPY . .
RUN go build -o mpe ./cmd/mpe

FROM alpine:latest
COPY --from=builder /app/mpe /usr/local/bin/
COPY policies/ /policies/

ENTRYPOINT ["mpe", "serve"]
CMD ["-b", "/policies/domain.yml", "--port", "9000"]
```

```bash
docker build -t mpe-server .
docker run -p 9000:9000 mpe-server
```
