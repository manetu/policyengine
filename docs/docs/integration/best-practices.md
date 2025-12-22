---
sidebar_position: 6
---

# Best Practices

This guide covers recommended patterns for implementing Policy Enforcement Points (PEPs) and integrating with the PolicyEngine.

## Policy Development: Start Strict, Iterate with Evidence

The PolicyEngine's observable architecture enables a powerful approach to access control: **start with strict policies and iteratively expand access based on observed needs**.

### Why This Matters

Traditional approaches to access control often fail at the Principle of Least Privilege because:

- It's hard to know what access is actually needed upfront
- Administrators grant broad permissions "just in case" to avoid blocking users
- Once granted, overly permissive access is rarely reviewed or tightened

The PolicyEngine solves this by making every decision observable through [AccessRecords](/concepts/audit), enabling evidence-based policy refinement.

### The Recommended Workflow

**1. Deploy Strict Initial Policies**

Start with policies that may be more restrictive than necessary. It's easier to safely expand access than to identify and close security gaps later:

```yaml
# Start with minimal access - only grant what you're certain is needed
roles:
  - mrn: "mrn:iam:role:new-service"
    name: new-service
    policy: "mrn:iam:policy:read-only"  # Start conservative
```

**2. Observe and Analyze Denials**

Monitor the AccessRecord stream for denied requests. These denials are your evidence of what additional access may be needed:

```bash
# Find denied requests (OSS example)
mpe serve ... 2>&1 | jq 'select(.decision == "DENY")'

# Analyze denial patterns
... | jq -r '.operation' | sort | uniq -c | sort -rn
```

**3. Validate Before Expanding**

Use [policy replay](/concepts/audit#policy-replay) to understand the impact of proposed changes before deployment:

1. Collect AccessRecords from production (including grants and denials)
2. Create a candidate policy with expanded permissions
3. Replay collected PORCs and compare decisions
4. Review which denials would become grants—are these all legitimate?

**4. Expand Precisely**

Grant only the specific access that was demonstrated necessary, then continue monitoring.

### Benefits of This Approach

- **Minimal attack surface**: Never grant more access than proven necessary
- **Evidence over speculation**: Decisions based on actual usage, not guesswork
- **Safe iteration**: Policy replay lets you preview changes before production impact
- **Continuous improvement**: Supports ongoing refinement as needs evolve

For a detailed walkthrough with examples, see [Iterative Policy Refinement](/concepts/audit#iterative-policy-refinement).

## PEP Design

### Keep PEPs Simple

The PEP's job is to formulate the request and enforce the decision—not to implement access control logic. Keep the logic in policies where it can be centrally managed and tested.

```go
// Good: PEP just builds PORC and enforces the decision
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
// Faster: Pass the map directly
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

### Consider Caching for Probe-Mode Checks

For UI capability checks (e.g., determining which buttons to show), you can use `probe=true` to disable audit logging and safely cache results. Probe mode is designed for scenarios where you need to check permissions without creating audit entries:

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

    // Use probe=true for UI checks - disables audit logging
    allowed := c.pdp.Authorize(ctx, buildPORC(principal, operation, resource), WithProbe(true))
    c.cache.Add(key, allowed)
    return allowed
}
```

:::warning
Only cache probe-mode results. Regular authorization checks (without `probe=true`) should never be cached, as this would bypass the audit log. See [Audit](/concepts/audit) for more information.
:::

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
# Test that an admin can read resources
mpe test decision -b domain.yml -i test-admin-read.json | jq .decision
# Expected: "GRANT"

# Test that a viewer cannot delete (using stdin)
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
