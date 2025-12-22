---
sidebar_position: 1
---

# Deployment

This section covers deploying the Manetu PolicyEngine in production environments.

:::tip Quick Navigation
- **Just getting started?** Follow the examples on this page
- **Planning your architecture?** See [Deployment Architecture](/deployment/architecture) for form-factors, scaling patterns, and decision guidance
- **Using Envoy?** See [Envoy Integration](/deployment/envoy-integration)
:::

## Deployment Options

<SectionHeader icon="standalone" level={3}>Standalone Server</SectionHeader>

Run the `mpe serve` command as a standalone decision-point process:

```bash
mpe serve -b domain.yml --port 9000
```

<SectionHeader icon="docker" level={3}>Docker Container</SectionHeader>

You may also run the server as a Docker container:

```bash
docker run -p 9000:9000 -v $PWD:/mnt ghcr.io/manetu/policyengine:latest serve -b /mnt/domain.yml --port 9000
```

<SectionHeader icon="kubernetes" level={3}>Kubernetes</SectionHeader>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mpe-pdp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mpe-pdp
  template:
    metadata:
      labels:
        app: mpe-pdp
    spec:
      containers:
      - name: mpe
        image: ghcr.io/manetu/policyengine:latest
        command: ["serve", "-b", "/mnt/domain.yml", "--port", "9000"]
        ports:
        - containerPort: 9000
        env:
        - name: MPE_LOG_LEVEL
          value: ".:info"
        - name: MPE_LOG_FORMATTER
          value: "json"
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        readinessProbe:
          grpc:
            port: 9000
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          grpc:
            port: 9000
          initialDelaySeconds: 10
          periodSeconds: 15
---
apiVersion: v1
kind: Service
metadata:
  name: mpe-pdp
spec:
  selector:
    app: mpe-pdp
  ports:
  - port: 9000
    targetPort: 9000
  type: ClusterIP
```

:::tip Premium Feature: Kubernetes Operator
The Community Edition requires manual deployment and configuration of decision points. The **Premium Edition** includes a Kubernetes Operator that automatically configures policy decision points as sidecars. This approach offers significant advantages:

- **Automatic scaling** — Decision points scale naturally with your application pods, eliminating the need to manually tune PDP capacity
- **Lower latency** — Sidecar deployment places the decision point adjacent to the PEP, minimizing network hops
- **Simplified operations** — No separate PDP infrastructure to manage; lifecycle is tied to your application
- **Consistent enforcement** — Every pod automatically receives policy enforcement without additional configuration
:::

## High Availability

### Multiple Replicas

Deploy multiple replicas for high availability:

- All replicas serve the same policies
- Load balancer distributes requests
- No shared state between replicas

### Health Checks

The server exposes gRPC health checks:

```yaml
readinessProbe:
  grpc:
    port: 9000
  initialDelaySeconds: 5
```

## Security

### Network Policy

Restrict access to the policy server:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mpe-server-policy
spec:
  podSelector:
    matchLabels:
      app: mpe-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          needs-authz: "true"
    ports:
    - port: 9000
```

### TLS

For production, configure TLS at the load balancer or service mesh level.

## Monitoring

### Metrics

Monitor these key metrics:
- Request latency (p50, p95, p99)
- Decision rate (allow/deny)
- Error rate

### Logging

Use structured logging for observability:

```bash
export MPE_LOG_FORMATTER=json
export MPE_LOG_LEVEL=.:info
```

:::tip Premium Feature: Advanced Observability
The Community Edition provides basic metrics and logging. The **Premium Edition** adds enterprise-grade observability including:
- **Audit storage and indexing** — Searchable history of all policy decisions
- **Audit history query** — Query past decisions by principal, resource, time range, and outcome
- **Decision replay with visual code coverage** — Replay historical decisions and visualize which policy paths were evaluated
:::

## Next Steps

- [Envoy Integration](/deployment/envoy-integration) - Integrate with Envoy proxy
