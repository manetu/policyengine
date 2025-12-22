---
sidebar_position: 3
---

# HTTP API

The HTTP API provides a language-agnostic interface for policy decisions. This is the recommended approach for most applications — it works with any language (Python, Java, TypeScript, Go, etc.), enables independent scaling of the policy decision service, and provides a seamless migration path to the Premium Edition. See [Choosing Your Integration Method](/integration#1-choose-your-integration-method) for a detailed comparison of integration options.

## Using `mpe serve`

The `mpe serve` command runs a standalone HTTP server for policy decisions:

```bash
mpe serve -b my-domain.yml --port 9000
```

This works for both **local development** and **production deployments**:

| Use Case | Description |
|----------|-------------|
| **Development** | Test HTTP-based PEP integration locally before deploying |
| **Production (Community)** | Run as a production PDP when Premium features aren't needed |
| **Premium migration** | Develop against the same API that Premium exposes |

The server exposes an HTTP endpoint at `POST /decision`. A SwaggerUI interface is available at http://localhost:9000/swagger-ui/ for interactive testing.

See [mpe serve](/reference/cli/serve) for full server configuration options.

## API Specification

### Endpoint

```
POST /decision
Content-Type: application/json
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `probe` | boolean | `false` | When `true`, disables audit logging for this request. Use for UI capability checks. |

### Request Body

A PORC expression as JSON:

```json
{
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
}
```

### Response Body

```json
{
  "allow": true
}
```

### Probe Mode

Use probe mode (`?probe=true`) to check permissions without generating audit entries. This is useful for UI capability checks—determining which buttons, menu items, or actions to display to users.

```bash
# Check if user can edit, without creating an audit entry
curl -X POST "http://localhost:9000/decision?probe=true" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"sub": "user@example.com", "mroles": ["mrn:iam:example.com:role:viewer"]},
    "operation": "api:documents:edit",
    "resource": "mrn:app:example:document:12345"
  }'
```

:::warning
Only use probe mode for UI capability checks. Actual access control decisions should always be audited (omit the `probe` parameter or set it to `false`). See [Audit](/concepts/audit) for more information.
:::

## Client Examples

### cURL  

```bash
curl -X POST http://localhost:9000/decision \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {
      "sub": "user@example.com",
      "mroles": ["mrn:iam:example.com:role:developer"]
    },
    "operation": "api:documents:read",
    "resource": "mrn:app:example:document:12345",
    "context": {}
  }'
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

type PDPClient struct {
    baseURL    string
    httpClient *http.Client
}

func NewPDPClient(baseURL string) *PDPClient {
    return &PDPClient{
        baseURL:    baseURL,
        httpClient: &http.Client{},
    }
}

type DecisionResponse struct {
    Allow bool `json:"allow"`
}

func (c *PDPClient) Authorize(porc map[string]interface{}) (bool, error) {
    body, err := json.Marshal(porc)
    if err != nil {
        return false, fmt.Errorf("failed to marshal PORC: %w", err)
    }

    req, err := http.NewRequest("POST", c.baseURL+"/decision", bytes.NewReader(body))
    if err != nil {
        return false, fmt.Errorf("failed to create request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return false, fmt.Errorf("failed to call PDP: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return false, fmt.Errorf("PDP returned status %d: %s", resp.StatusCode, string(body))
    }

    var decision DecisionResponse
    if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
        return false, fmt.Errorf("failed to decode response: %w", err)
    }

    return decision.Allow, nil
}

func main() {
    client := NewPDPClient("http://localhost:9000")

    porc := map[string]interface{}{
        "principal": map[string]interface{}{
            "sub":    "user@example.com",
            "mroles": []string{"mrn:iam:example.com:role:developer"},
        },
        "operation": "api:documents:read",
        "resource":  "mrn:app:example:document:12345",
        "context":   map[string]interface{}{},
    }

    allowed, err := client.Authorize(porc)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Decision: %v\n", allowed)
}
```

### Python

```python
import requests
from typing import Any

class PDPClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def authorize(self, porc: dict[str, Any]) -> bool:
        """
        Call the PDP to authorize a request.

        Args:
            porc: A PORC expression dictionary

        Returns:
            True if access is granted, False otherwise

        Raises:
            requests.RequestException: If the HTTP request fails
        """
        response = self.session.post(
            f"{self.base_url}/decision",
            json=porc,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json().get("allow", False)


# Example usage
if __name__ == "__main__":
    client = PDPClient("http://localhost:9000")

    porc = {
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
    }

    try:
        allowed = client.authorize(porc)
        print(f"Access {'GRANTED' if allowed else 'DENIED'}")
    except requests.RequestException as e:
        print(f"PDP error: {e}")
```

### JavaScript/TypeScript

```typescript
interface Principal {
  sub: string;
  mroles?: string[];
  mgroups?: string[];
  scopes?: string[];
  mclearance?: string;
  mannotations?: Record<string, unknown>;
}

interface PORC {
  principal: Principal;
  operation: string;
  resource: string | Record<string, unknown>;
  context?: Record<string, unknown>;
}

interface DecisionResponse {
  allow: boolean;
}

class PDPClient {
  constructor(private baseUrl: string) {}

  async authorize(porc: PORC): Promise<boolean> {
    const response = await fetch(`${this.baseUrl}/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(porc),
    });

    if (!response.ok) {
      throw new Error(`PDP returned status ${response.status}`);
    }

    const decision: DecisionResponse = await response.json();
    return decision.allow;
  }
}

// Example usage
async function main() {
  const client = new PDPClient('http://localhost:9000');

  const porc: PORC = {
    principal: {
      sub: 'user@example.com',
      mroles: ['mrn:iam:example.com:role:developer'],
      mclearance: 'MODERATE',
    },
    operation: 'api:documents:read',
    resource: 'mrn:app:example:document:12345',
    context: {
      source_ip: '192.168.1.100',
    },
  };

  try {
    const allowed = await client.authorize(porc);
    console.log(`Access ${allowed ? 'GRANTED' : 'DENIED'}`);
  } catch (error) {
    console.error('PDP error:', error);
  }
}

main();
```

### Java

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

public class PDPClient {
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public PDPClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public boolean authorize(Map<String, Object> porc) throws Exception {
        String body = objectMapper.writeValueAsString(porc);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/decision"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = httpClient.send(
            request,
            HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new RuntimeException("PDP returned status " + response.statusCode());
        }

        Map<String, Object> decision = objectMapper.readValue(
            response.body(),
            Map.class
        );

        return Boolean.TRUE.equals(decision.get("allow"));
    }

    public static void main(String[] args) throws Exception {
        PDPClient client = new PDPClient("http://localhost:9000");

        Map<String, Object> porc = Map.of(
            "principal", Map.of(
                "sub", "user@example.com",
                "mroles", java.util.List.of("mrn:iam:example.com:role:developer"),
                "mclearance", "MODERATE"
            ),
            "operation", "api:documents:read",
            "resource", "mrn:app:example:document:12345",
            "context", Map.of(
                "source_ip", "192.168.1.100"
            )
        );

        boolean allowed = client.authorize(porc);
        System.out.println("Access " + (allowed ? "GRANTED" : "DENIED"));
    }
}
```

## Production Considerations

### Connection Pooling

Reuse HTTP connections for better performance:

```python
# Python - reuse session
client = PDPClient("http://localhost:9000")
# session is reused across calls

# Go - configure transport
httpClient := &http.Client{
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
    },
}
```

### Timeouts

Configure appropriate timeouts:

```go
httpClient := &http.Client{
    Timeout: 500 * time.Millisecond,
}
```

### Retries

Consider retry logic for transient failures:

```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retries = Retry(total=3, backoff_factor=0.1)
session.mount('http://', HTTPAdapter(max_retries=retries))
```

## Premium Considerations <FeatureChip variant="premium" label="Premium Only" size="medium"/>

All HTTP-based options use the same API.  This guide helps you navigate as you migrate from Community to Premium.

### Migration from Community

Migrating from Community to Premium—whether as a sidecar or standalone service-is as simple as updating your endpoint URL. No code changes required.

### Development

You can develop locally with [`mpe serve`](/reference/cli/serve), then deploy to Premium production by simply updating your endpoint URL.

### Deployment Options

The Premium Edition can be deployed in multiple configurations:

| Deployment | Latency | Scaling | Best For |
|------------|---------|---------|----------|
| **Kubernetes sidecar** | Localhost round-trip | 1:1 with application (Operator-managed) | K8s environments wanting automated scaling |
| **Standalone service** | Network round-trip | Independent | Non-K8s environments, shared PDP |

Regardless of the deployment model, Premium features such as centralized audit logs, decision replay, external resource resolution, and policy coordination are available.

For a full comparison of HTTP API vs. the embedded Go library, see [Choosing Your Integration Method](/integration#1-choose-your-integration-method).
