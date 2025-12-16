---
sidebar_position: 6
---

# Best Practices

This guide covers recommended patterns for implementing Policy Enforcement Points (PEPs) and integrating with the PolicyEngine.

## PEP Design

### Keep PEPs Simple

The PEP's job is to formulate the request and enforce the decision—not to implement access control logic. Keep the logic in policies where it can be centrally managed and tested.

```go
// Good: PEP just builds PORC and enforces decision
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        porc := m.buildPORC(r)

        allowed, err := m.pdp.Authorize(r.Context(), porc)
        if err != nil || !allowed {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// Bad: PEP contains access control logic
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := extractClaims(r)

        // Don't do this - put this logic in policies!
        if claims.Role == "admin" {
            next.ServeHTTP(w, r)
            return
        }

        if r.Method == "GET" && claims.Role == "viewer" {
            next.ServeHTTP(w, r)
            return
        }

        http.Error(w, "Forbidden", http.StatusForbidden)
    })
}
```

### Use Consistent Operation Naming

Establish a naming convention for operations and document it:

```
<subsystem>:<resource-class>:<verb>
```

This makes it easier to write policies that match patterns:

```rego
# Allow all read operations across subsystems
allow {
    glob.match("*:*:read", [], input.operation)
}

# Allow all operations on a specific resource type
allow {
    glob.match("api:users:*", [], input.operation)
}
```

### Map HTTP Methods Consistently

When building operations from HTTP requests:

| HTTP Method | Verb |
|-------------|------|
| GET | read |
| POST | create |
| PUT | update |
| PATCH | update |
| DELETE | delete |

```go
func httpMethodToVerb(method string) string {
    switch strings.ToUpper(method) {
    case "GET":
        return "read"
    case "POST":
        return "create"
    case "PUT", "PATCH":
        return "update"
    case "DELETE":
        return "delete"
    default:
        return strings.ToLower(method)
    }
}
```

## Resource Handling

### Prefer MRN Strings

Using MRN strings with resource resolution:

- Simplifies PEP code
- Centralizes resource metadata management
- Allows policy changes without code deployments

```go
// Recommended: Use MRN string
porc["resource"] = fmt.Sprintf("mrn:app:%s:document:%s", service, docID)

// Only when needed: Use fully-qualified descriptor
porc["resource"] = map[string]interface{}{
    "id":    fmt.Sprintf("mrn:app:%s:document:%s", service, docID),
    "owner": doc.OwnerEmail,
    // ...
}
```

### Build Meaningful MRNs

Create MRNs that reflect your resource hierarchy:

```go
// Good: Descriptive, hierarchical MRNs
"mrn:app:billing:invoice:INV-2024-001"
"mrn:api:users:profile:user-12345"
"mrn:storage:documents:report:annual-2024"

// Bad: Opaque, non-descriptive MRNs
"mrn:x:y:z:abc123"
"mrn:resource:1234"
```

## Error Handling

### Handle PDP Errors Gracefully

**Fail Closed:** You should treat PDP failures as default-DENY.

```go
allowed, err := pdp.Authorize(ctx, porc)
if err != nil {
    log.Printf("PDP unavailable, denying access: %v", err)
    return deny()
}
```

### Distinguish Error Types

```go
allowed, err := pdp.Authorize(ctx, porc)
if err != nil {
    // Log the error for debugging
    log.Printf("Authorization error: %v", err)

    // Return 500 for PDP errors (not 403)
    http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    return
}

if !allowed {
    // Return 403 for policy denials
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

## Performance

### Reuse Connections

For HTTP API integration, reuse connections:

```go
// Create client once, reuse for all requests
var pdpClient = &http.Client{
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     90 * time.Second,
    },
    Timeout: 500 * time.Millisecond,
}
```

### Use Maps Instead of JSON Strings

When using the embedded library, pass maps directly to avoid JSON parsing:

```go
// Faster: Pass map directly
porc := map[string]interface{}{
    "principal": principal,
    "operation": operation,
    "resource":  resource,
    "context":   context,
}
allowed, _ := pe.Authorize(ctx, porc)

// Slower: JSON string requires parsing
porcJSON := `{"principal": {...}, ...}`
allowed, _ := pe.Authorize(ctx, porcJSON)
```

### Consider Caching for Repeated Checks

For UI capability checks (e.g., which buttons to show), consider short-term caching:

```go
type PermissionCache struct {
    cache *lru.Cache
    ttl   time.Duration
}

func (c *PermissionCache) CanPerform(ctx context.Context, principal, operation, resource string) bool {
    key := fmt.Sprintf("%s:%s:%s", principal, operation, resource)

    if cached, ok := c.cache.Get(key); ok {
        return cached.(bool)
    }

    allowed := c.pdp.Authorize(ctx, buildPORC(principal, operation, resource))
    c.cache.Add(key, allowed)
    return allowed
}
```

## Testing

### Test PEPs with Mock PDP

```go
type MockPDP struct {
    decisions map[string]bool
}

func (m *MockPDP) Authorize(ctx context.Context, porc interface{}) (bool, error) {
    // Return configured decision or default to deny
    key := buildKey(porc)
    if decision, ok := m.decisions[key]; ok {
        return decision, nil
    }
    return false, nil
}

func TestAuthMiddleware(t *testing.T) {
    mockPDP := &MockPDP{
        decisions: map[string]bool{
            "user@example.com:api:users:read:mrn:app:users": true,
        },
    }

    middleware := NewAuthMiddleware(mockPDP)
    // Test the middleware...
}
```

### Test Policy Decisions Separately

Use `mpe test decision` to test policies independently of PEP code. Create individual PORC input files for each test scenario:

**test-admin-read.json:**
```json
{
  "principal": {
    "sub": "admin@example.com",
    "mroles": ["mrn:iam:role:admin"]
  },
  "operation": "api:documents:read",
  "resource": {
    "id": "mrn:app:docs:document:123"
  }
}
```

```bash
# Test that admin can read resources
mpe test decision -b domain.yml -i test-admin-read.json | jq .decision
# Expected: "GRANT"

# Test that viewer cannot delete (using stdin)
echo '{"principal":{"sub":"viewer@example.com","mroles":["mrn:iam:role:viewer"]},"operation":"api:documents:delete","resource":{"id":"mrn:app:docs:document:123"}}' | \
  mpe test decision -b domain.yml -i -  | jq .decision
# Expected: "DENY"
```

For comprehensive policy testing, consider creating a shell script that runs multiple test cases and validates the expected outcomes.

## Security

### Validate JWT Before Building PORC

Always validate JWTs before trusting their claims:

```go
func extractClaims(r *http.Request) (*Claims, error) {
    token := extractBearerToken(r)
    if token == "" {
        return nil, errors.New("no token provided")
    }

    // Validate signature, expiration, issuer, audience
    claims, err := validateAndParseJWT(token)
    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    return claims, nil
}
```

### Don't Trust Client-Provided Resource Metadata

When using fully-qualified resource descriptors, get metadata from authoritative sources:

```go
// Good: Get metadata from your database
doc := db.GetDocument(docID)
resource := map[string]interface{}{
    "id":             doc.MRN,
    "owner":          doc.Owner,
    "classification": doc.Classification,
}

// Bad: Trust client-provided metadata
resource := map[string]interface{}{
    "id":             r.URL.Path,
    "classification": r.Header.Get("X-Classification"), // Don't do this!
}
```

### Sanitize Context Data

Be careful about what you include in context:

```go
context := map[string]interface{}{
    "source_ip":  r.RemoteAddr,
    "user_agent": r.UserAgent(),
    "request_id": r.Header.Get("X-Request-ID"),
    // Don't include sensitive data like passwords or tokens
}
```
