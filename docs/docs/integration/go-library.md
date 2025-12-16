---
sidebar_position: 2
---

# Embedded Go Library  

<FeatureChip variant="oss" label="OSS Only"/>

For Go applications, you can embed the PolicyEngine directly using the `github.com/manetu/policyengine` package. This approach offers the lowest latency since policy evaluation happens in-process.

## Installation

```bash
go get github.com/manetu/policyengine
```

## Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/manetu/policyengine/pkg/core"
)

func main() {
    // Create a new PolicyEngine instance
    pe, err := core.NewPolicyEngine()
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

## Using Maps for Efficiency

The `Authorize` method accepts either a JSON string or a `map[string]interface{}`. Using a map directly avoids JSON parsing overhead:

```go
porc := map[string]interface{}{
    "principal": map[string]interface{}{
        "sub":        "user@example.com",
        "mroles":     []string{"mrn:iam:example.com:role:developer"},
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

## Configuration Options

The PolicyEngine can be configured with various options:

```go
import (
    "github.com/manetu/policyengine/pkg/core"
    "github.com/manetu/policyengine/pkg/core/options"
    "github.com/manetu/policyengine/pkg/core/accesslog"
)

pe, err := core.NewPolicyEngine(
    options.WithAccessLog(accesslog.NewStdoutFactory()),
    // Add additional options as needed
)
```

### Available Options

| Option | Description |
|--------|-------------|
| `WithAccessLog(factory)` | Configure access logging |
| `WithBackend(factory)` | Configure the backend service |
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

func NewAuthMiddleware() (*AuthMiddleware, error) {
    pe, err := core.NewPolicyEngine()
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
    middleware, err := NewAuthMiddleware()
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

## When to Use the Embedded Library

The embedded library is ideal when:

- Your application is written in Go
- You need the lowest possible latency (no network overhead)
- You want a single deployment artifact
- Policy updates can be deployed with application updates

For non-Go applications or when you need to share a PDP across services, see [HTTP API](/integration/http-api).

:::note Open Source Edition Only
The embedded Go library is only available in the open source edition. The [Premium Edition](/#open-source-and-premium-editions) requires integration via the gRPC/HTTP interface to enable enterprise features such as centralized audit and policy coordination. If you anticipate needing Premium features, consider using the [HTTP API](/integration/http-api) instead — you can migrate to Premium by simply changing the endpoint URL.
:::
