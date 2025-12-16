---
sidebar_position: 9
---

# Mappers Schema

## Definition

```yaml
spec:
  mappers:
    - name: string          # Required: Human-readable name
      selector: []          # Required: Regex patterns to match
      rego: string          # Required: Rego code (or rego_filename)
      rego_filename: string # Alternative: External file path
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name |
| `selector` | array | Yes | List of regex patterns |
| `rego` | string | See below | Inline Rego code |
| `rego_filename` | string | See below | Path to external `.rego` file |

### Rego Code Fields

The `rego` and `rego_filename` fields specify where the Rego code comes from:

| Document Kind | `rego` | `rego_filename` |
|---------------|--------|-----------------|
| `PolicyDomain` | Required | Not supported |
| `PolicyDomainReference` | Optional | Optional |

For `PolicyDomainReference`, you must provide either `rego` (inline) or `rego_filename` (external file), but not both. Using `rego_filename` is recommended for development as it enables IDE syntax highlighting and cleaner version control diffs.

See [PolicyDomain vs PolicyDomainReference](/reference/schema/#policydomain-vs-policydomainreference) for more details.

## Rego Requirements

Mappers must:
- Declare `package mapper`
- Export a `porc` variable with the PORC structure

```rego
package mapper

porc := {
    "principal": { ... },
    "operation": "...",
    "resource": { ... },
    "context": { ... }
}
```

## Selectors

Selectors match against infrastructure identifiers (e.g., service account names, SPIFFE IDs). First match wins.

## Examples

### Basic Mapper

```yaml
mappers:
  - name: default
    selector:
      - ".*"
    rego: |
      package mapper

      porc := {
          "principal": input.claims,
          "operation": input.operation,
          "resource": input.resource,
          "context": input
      }
```

### Envoy HTTP Mapper

```yaml
mappers:
  - name: http-mapper
    selector:
      - ".*"
    rego: |
      package mapper
      import rego.v1

      default claims := {}

      get_default(obj, key, fallback) := obj[key] if obj[key]
      get_default(obj, key, fallback) := fallback if not obj[key]

      method := lower(get_default(input.request.http, "method", "GET"))
      path := get_default(input.request.http, "path", "/")
      headers := get_default(input.request.http, "headers", {})

      # Extract service from SPIFFE ID
      dest := split(input.destination.principal, "/")
      service := dest[count(dest) - 1]

      # Extract JWT
      auth := headers.authorization
      token := split(auth, "Bearer ")[1] if auth
      claims := io.jwt.decode(token)[1] if token

      porc := {
          "principal": claims,
          "operation": sprintf("%s:http:%s", [service, method]),
          "resource": sprintf("mrn:http:%s%s", [service, path]),
          "context": input
      }
```

The PolicyEngine's [Resource Resolution](/integration/resource-resolution) enriches MRN strings with metadata at evaluation time. Use the Fully Qualified Descriptor format only when the PEP has context the backend cannot determine.

### Service-Specific Mappers

```yaml
mappers:
  # Frontend service mapper
  - name: frontend
    selector:
      - ".*frontend.*"
    rego: |
      package mapper
      # Frontend-specific logic...

  # API service mapper
  - name: api
    selector:
      - ".*api-server.*"
    rego: |
      package mapper
      # API-specific logic...

  # Default fallback
  - name: default
    selector:
      - ".*"
    rego: |
      package mapper
      # Default logic...
```

### Using External File

```yaml
# In PolicyDomainReference
mappers:
  - name: http-mapper
    selector:
      - ".*"
    rego_filename: mappers/http.rego
```
