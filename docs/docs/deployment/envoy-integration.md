---
sidebar_position: 2
---

# Envoy Integration

Integrate the Manetu PolicyEngine with Envoy proxy for service mesh authorization.

## Overview

The PolicyEngine can serve as an [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter) service, making authorization decisions for requests passing through Envoy.

```
Client → Envoy → ext_authz → MPE → Decision
                    ↓
              Allow/Deny
```

## Starting the Envoy Server

Start the PolicyEngine with the Envoy protocol:

```bash
mpe serve -b domain.yml -p envoy --port 9001
```

## Envoy Configuration

### HTTP Filter

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: ext_authz
        timeout: 0.25s
      transport_api_version: V3
      failure_mode_allow: false
      with_request_body:
        max_request_bytes: 8192
        allow_partial_message: true
```

### Cluster Configuration

```yaml
clusters:
  - name: ext_authz
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
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

## Mapper Configuration

Create a mapper to transform Envoy requests to PORC:

```yaml
mappers:
  - name: envoy-http
    selector:
      - ".*"
    rego: |
      package mapper
      import rego.v1

      # Safe accessor
      get_default(obj, key, fallback) := obj[key] if obj[key]
      get_default(obj, key, fallback) := fallback if not obj[key]

      # Extract HTTP details
      request := input.request.http
      method := lower(get_default(request, "method", "GET"))
      path := get_default(request, "path", "/")
      headers := get_default(request, "headers", {})

      # Extract service from SPIFFE ID
      dest_parts := split(input.destination.principal, "/")
      service := dest_parts[count(dest_parts) - 1]

      # Extract JWT claims
      default claims := {}
      auth := headers.authorization
      bearer := substring(auth, 7, -1) if startswith(auth, "Bearer ")
      claims := io.jwt.decode(bearer)[1] if bearer

      # Build PORC
      porc := {
          "principal": {
              "sub": claims.sub,
              "mroles": claims.mroles,
              "mgroups": claims.mgroups,
              "scopes": claims.scope,
              "mclearance": claims.clearance,
              "mannotations": claims.annotations
          },
          "operation": sprintf("%s:http:%s", [service, method]),
          "resource": sprintf("mrn:http:%s%s", [service, path]),
          "context": {
              "source_ip": input.source.address,
              "timestamp": time.now_ns(),
              "original": input
          }
      }
```

:::tip[Resource Format]
This example uses the simple MRN string format, which is the recommended approach. The PolicyEngine's [Resource Resolution](/integration/resource-resolution) enriches resources with metadata at evaluation time. Use the Fully Qualified Descriptor format only when the mapper has context that the backend cannot determine.
:::

## Istio Integration

For Istio service mesh, configure an AuthorizationPolicy:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ext-authz
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-ingressgateway
  action: CUSTOM
  provider:
    name: mpe-authz
  rules:
  - to:
    - operation:
        paths: ["/*"]
```

Configure the extension provider in the Istio mesh config:

```yaml
extensionProviders:
- name: mpe-authz
  envoyExtAuthzGrpc:
    service: mpe-server.default.svc.cluster.local
    port: 9001
```

## Testing

Test the integration locally:

```bash
# Start the server
mpe serve -b domain.yml -p envoy --port 9001

# Test with grpcurl
grpcurl -plaintext \
  -d '{"request":{"http":{"method":"GET","path":"/api/users"}}}' \
  localhost:9001 \
  envoy.service.auth.v3.Authorization/Check
```

## Troubleshooting

### Enable Debug Logging

```bash
MPE_LOG_LEVEL=.:debug mpe serve -b domain.yml -p envoy --port 9001
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Connection refused | Server not running | Check server is started |
| Timeout | Slow policy evaluation | Optimize policies, increase timeout |
| Always denied | Missing mapper | Ensure mapper matches requests |
| JWT errors | Invalid token format | Check JWT format in mapper |

## Best Practices

1. **Fail closed**: Set `failure_mode_allow: false`
2. **Set timeouts**: Configure appropriate timeouts
3. **Monitor latency**: Track authorization latency
4. **Test mappers**: Verify mappers handle all request patterns
5. **Log decisions**: Enable audit logging for debugging