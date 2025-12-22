---
sidebar_position: 2
sidebar_label: Embedded Go Library
---

# Embedded Go Library <FeatureChip variant="community" label="Community Only" size="medium"/>

For Go applications, you can embed the PolicyEngine directly using the `github.com/manetu/policyengine` package. This approach offers the lowest latency since policy evaluation happens in-process, but is only available in the Community Edition and does not offer an upgrade path to the Premium offering. See [Choosing Your Integration Method](/integration#1-choose-your-integration-method) for a detailed comparison of integration options.

:::warning
The embedded Go library is only available in the Community Edition — it cannot connect to Premium services.  If you decide later to upgrade to Premium, you will need to port your PEPs to the [HTTP-API](/integration/http-api)
:::

## Installation

```bash
go get github.com/manetu/policyengine
```

## Basic Usage

The simplest way to create a PolicyEngine is with `NewLocalPolicyEngine`, which loads policy domains from YAML files:

```go
package main

import (
    "context"
    "log"

    "github.com/manetu/policyengine/pkg/core"
)

func main() {
    // Create a PolicyEngine from local policy domain files
    pe, err := core.NewLocalPolicyEngine([]string{
        "./policies/policydomain.yaml",
    })
    if err != nil {
        log.Fatalf("Failed to create PolicyEngine: %v", err)
    }

    // Create a PORC expression as a JSON string
    porc := `{
        "principal": {
            "sub": "user@example.com",
            "mroles": ["mrn:iam:example.com:role:developer"],
            "mclearance": "MODERATE"
        },
        "operation": "api:documents:read",
        "resource": "mrn:app:example:document:12345",
        "context": {
            "source_ip": "192.168.1.100"
        }
    }`

    // Authorize the request
    ctx := context.Background()
    allowed, err := pe.Authorize(ctx, porc)
    if err != nil {
        log.Fatalf("Authorization error: %v", err)
    }

    if allowed {
        log.Println("Access GRANTED")
    } else {
        log.Println("Access DENIED")
    }
}
```

### Loading Multiple Domains

You can load multiple policy domain files. Domains are loaded in order, with later domains taking precedence for name collisions:

```go
pe, err := core.NewLocalPolicyEngine([]string{
    "./policies/base-domain.yaml",      // Common policies
    "./policies/app-domain.yaml",       // Application-specific policies
})
```

## Using Maps for Efficiency

The `Authorize` method accepts either a JSON string or a `map[string]interface{}`. Using a map directly avoids JSON parsing overhead:

```go
porc := map[string]interface{}{
    "principal": map[string]interface{}{
        "sub":        "user@example.com",
        "mroles":     []interface{}{"mrn:iam:example.com:role:developer"},
        "mclearance": "MODERATE",
    },
    "operation": "api:documents:read",
    "resource":  "mrn:app:example:document:12345",
    "context": map[string]interface{}{
        "source_ip": "192.168.1.100",
    },
}

allowed, err := pe.Authorize(ctx, porc)
```

:::warning Array Type Compatibility
When constructing PORC maps directly in Go, use `[]interface{}` for array fields (like `mroles`, `mgroups`, `scopes`), **not** `[]string`. The PolicyEngine is designed to work with structures unmarshalled via `json.Unmarshal()`, which converts JSON arrays into `[]interface{}` rather than `[]string`.

```go
// ✓ Correct - matches json.Unmarshal behavior
"mroles": []interface{}{"mrn:iam:example.com:role:admin", "mrn:iam:example.com:role:user"},

// ✗ Incorrect - will cause type mismatch errors
"mroles": []string{"mrn:iam:example.com:role:admin", "mrn:iam:example.com:role:user"},
```

This is not an issue when passing a JSON string to `Authorize`, as the internal unmarshalling handles the conversion automatically.
:::

## Configuration Options

The PolicyEngine can be configured with various options:

```go
import (
    "github.com/manetu/policyengine/pkg/core"
    "github.com/manetu/policyengine/pkg/core/options"
    "github.com/manetu/policyengine/pkg/core/accesslog"
)

pe, err := core.NewLocalPolicyEngine(
    []string{"./policies/policydomain.yaml"},
    options.WithAccessLog(accesslog.NewStdoutFactory()),
    // Add additional options as needed
)
```

### Available Options

| Option | Description |
|--------|-------------|
| `WithAccessLog(factory)` | Configure access logging |
| `WithCompilerOptions(opts...)` | Configure OPA compiler options |

## Probe Mode

Use probe mode to check permissions without generating audit logs. This is useful for UI capability checks—for example, determining whether to show an "Edit" button:

```go
allowed, err := pe.Authorize(ctx, porc, options.SetProbeMode(true))
```

When probe mode is enabled:
- Policies are evaluated normally
- No audit records are generated
- Useful for pre-flight permission checks

:::warning
Only use probe mode for UI capability checks. Actual access control decisions should always be audited (omit the probe option or set it to `false`). See [Audit](/concepts/audit) for more information.
:::

## Complete Middleware Example

Here's a complete HTTP middleware PEP implementation:

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"

    "github.com/manetu/policyengine/pkg/core"
)

type AuthMiddleware struct {
    pe core.PolicyEngine
}

func NewAuthMiddleware(policyDomains []string) (*AuthMiddleware, error) {
    pe, err := core.NewLocalPolicyEngine(policyDomains)
    if err != nil {
        return nil, err
    }
    return &AuthMiddleware{pe: pe}, nil
}

func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract claims from JWT (use proper JWT validation in production)
        claims := extractClaims(r)
        if claims == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Build PORC expression
        porc := map[string]interface{}{
            "principal": map[string]interface{}{
                "sub":          claims["sub"],
                "mroles":       claims["mroles"],
                "mgroups":      claims["mgroups"],
                "scopes":       claims["scope"],
                "mclearance":   claims["mclearance"],
                "mannotations": claims["mannotations"],
            },
            "operation": fmt.Sprintf("api:%s:%s",
                extractResourceType(r.URL.Path),
                strings.ToLower(r.Method)),
            "resource": extractResourceMRN(r.URL.Path),
            "context": map[string]interface{}{
                "source_ip":  r.RemoteAddr,
                "user_agent": r.UserAgent(),
                "method":     r.Method,
                "path":       r.URL.Path,
            },
        }

        // Call PDP
        allowed, err := m.pe.Authorize(r.Context(), porc)
        if err != nil {
            log.Printf("PDP error: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        if !allowed {
            log.Printf("Access denied: sub=%s operation=%s resource=%s",
                claims["sub"], porc["operation"], porc["resource"])
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        // Access granted - proceed
        next.ServeHTTP(w, r)
    })
}

func extractClaims(r *http.Request) map[string]interface{} {
    // Implementation: Parse and validate JWT from Authorization header
    return nil // placeholder
}

func extractResourceType(path string) string {
    // Implementation: Extract resource type from URL path
    return "resource" // placeholder
}

func extractResourceMRN(path string) string {
    // Implementation: Build MRN from URL path
    return "mrn:app:example:resource:id" // placeholder
}

func main() {
    // Load policy domains from YAML files
    policyDomains := []string{"./policies/policydomain.yaml"}

    middleware, err := NewAuthMiddleware(policyDomains)
    if err != nil {
        log.Fatalf("Failed to create auth middleware: %v", err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
    })

    handler := middleware.Handler(mux)
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", handler))
}
```

