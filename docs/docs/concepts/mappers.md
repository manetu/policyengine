---
sidebar_position: 13
---

# Mappers

**Mappers** are an optional feature that transforms non-PORC inputs into [PORC expressions](/concepts/porc) for policy evaluation. They are only needed when integrating with systems that cannot construct PORC expressions natively.

## When to Use Mappers

Mappers are designed for **limited integration scenarios** where the Policy Enforcement Point (PEP) has no ability to construct PORC expressions directly. The primary use case is integration with third-party systems that use fixed protocols.

### Primary Use Case: Envoy/Istio Integration

When using the Manetu PolicyEngine with Envoy's [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto) protocol, the request format is dictated by Envoy—not by Manetu. Mappers provide an intermediate transformation layer:

```
Envoy ext_authz Request → Mapper → PORC → Policy Evaluation
```

### When NOT to Use Mappers

**Most integrations should NOT use mappers.** If you're building a PEP in your own application, you should construct PORC expressions directly in your native programming language:

| Scenario | Recommendation |
|----------|---------------|
| Custom application with Go/Java/Python/etc. | Build PORC directly in your code |
| API gateway you control | Build PORC in gateway middleware |
| Envoy/Istio service mesh | Use mappers (Envoy protocol is fixed) |
| Third-party system with fixed protocol | Use mappers if protocol can't be changed |

Building PORC directly in your application code is:
- **More efficient**: No additional transformation step
- **Easier to debug**: Logic is in your familiar language
- **More flexible**: Full access to application context
- **Type-safe**: Leverage your language's type system

See the [Integration Guide](/integration) for examples of building PORC expressions directly.

## How Mappers Work

Mappers are Rego programs that receive the raw input and produce a `porc` output variable:

```yaml
spec:
  mappers:
    - name: envoy-mapper
      selector:
        - ".*"  # Regex pattern to match requests
      rego: |
        package mapper

        porc := {
            "principal": { ... },
            "operation": "...",
            "resource": { ... },
            "context": { ... }
        }
```

### Selector Patterns

Selectors determine which mapper handles a request. Mappers are evaluated in order; the first match wins:

```yaml
spec:
  mappers:
    - name: frontend-mapper
      selector:
        - ".*frontend.*"
      rego: |
        package mapper
        # Frontend-specific mapping...

    - name: default-mapper
      selector:
        - ".*"
      rego: |
        package mapper
        # Default mapping...
```

## Envoy Integration Example

The following example shows a mapper for Envoy's ext_authz protocol:

```rego
package mapper

import rego.v1

# Safe accessor with default
get_default(obj, key, fallback) := obj[key] if obj[key]
get_default(obj, key, fallback) := fallback if not obj[key]

# Extract HTTP details from Envoy request
method := lower(get_default(input.request.http, "method", "GET"))
path := get_default(input.request.http, "path", "/")
headers := get_default(input.request.http, "headers", {})

# Extract service from SPIFFE ID
dest := split(input.destination.principal, "/")
service := dest[count(dest) - 1]

# Extract JWT claims from Authorization header
default claims := {}
auth := headers.authorization
token := split(auth, "Bearer ")[1] if auth
claims := io.jwt.decode(token)[1] if token

# Build the PORC expression
porc := {
    "principal": claims,
    "operation": sprintf("%s:http:%s", [service, method]),
    "resource": sprintf("mrn:http:%s%s", [service, path]),
    "context": input
}
```

:::tip[Resource Format]
This example uses the simple **MRN string** format, which is the recommended approach. The PolicyEngine's [Resource Resolution](/integration/resource-resolution) enriches resources with metadata at evaluation time.

Use the **Fully Qualified Descriptor** format only when the PEP has context that the backend cannot determine.
:::

## Testing Mappers

Test mappers with sample inputs:

```bash
# Create Envoy-style input
cat > envoy-input.json << 'EOF'
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
EOF

# Test mapper output
mpe test mapper -b my-domain.yml -i envoy-input.json
```

## Best Practices

1. **Prefer native PORC construction**: Only use mappers when you cannot control the input format
2. **Keep mappers simple**: Complex business logic belongs in policies, not mappers
3. **Handle missing fields gracefully**: Use defaults for optional fields
4. **Validate inputs**: Check for required fields before processing
5. **Use Rego v1**: Include `import rego.v1` for latest syntax

## Related Concepts

- **[PORC Expressions](/concepts/porc)**: The format mappers produce
- **[Integration Guide](/integration)**: Building PEPs that construct PORC directly
- **[Envoy Integration](/deployment/envoy-integration)**: Deploying with Envoy/Istio

