# Manetu PolicyEngine

[![CI](https://github.com/manetu/policyengine/actions/workflows/ci.yml/badge.svg)](https://github.com/manetu/policyengine/actions/workflows/ci.yml)
[![CodeQL](https://github.com/manetu/policyengine/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/manetu/policyengine/actions/workflows/github-code-scanning/codeql)
[![Go Report Card](https://goreportcard.com/badge/github.com/manetu/policyengine)](https://goreportcard.com/report/github.com/manetu/policyengine)
[![codecov](https://codecov.io/gh/manetu/policyengine/branch/main/graph/badge.svg)](https://codecov.io/gh/manetu/policyengine)
[![Go Reference](https://pkg.go.dev/badge/github.com/manetu/policyengine.svg)](https://pkg.go.dev/github.com/manetu/policyengine)
[![License](https://img.shields.io/github/license/manetu/policyengine)](LICENSE)

A high-performance, programmable access-control and governance layer for protecting APIs and sensitive data using [Policy-Based Access Control (PBAC)](https://manetu.github.io/policyengine/concepts/pbac).

## Open Source Edition

This is the **open source edition** of the Manetu PolicyEngine — a fully functional policy engine that you can embed in your applications or run as a standalone service. It provides everything you need to author, test, and enforce access control policies.

For organizations requiring enterprise-grade audit storage, centralized policy administration, a Kubernetes Operator for sidecar automation, and advanced observability features, a **Premium Edition** is available through [Manetu](https://manetu.com). See the [documentation](https://manetu.github.io/policyengine/) for a full feature comparison.

## Overview

The Manetu PolicyEngine (MPE) enables organizations to enforce fine-grained, context-aware access control policies using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) and the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policy language.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Application   │────▶│  Policy Engine  │────▶│   OPA/Rego      │
│   (PEP)         │     │  (PDP)          │     │   Evaluation    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Key Features

- **OPA Integration** - Built on Open Policy Agent for industry-standard policy evaluation
- **PolicyDomain Model** - Self-contained bundles organizing policies, roles, scopes, and mappers
- **Multi-Phase Evaluation** - Layered decision process (operation, identity, resource, scope policies)
- **Developer Tooling** - CLI for building, linting, testing, and serving policies
- **Flexible Deployment** - Embeddable Go library or standalone gRPC/HTTP service

## Quick Start

### Install the CLI

**Using Homebrew (macOS/Linux):**

```bash
brew tap manetu/tap
brew install mpe
```

**Using Go:**

```bash
go install github.com/manetu/policyengine/cmd/mpe@latest
```

### Create a PolicyDomain

```yaml
# my-domain.yml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: my-first-domain
spec:
  policies:
    - mrn: &allow-all "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = false
        allow { input.principal != {} }

  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      policy: *allow-all
```

### Validate and Test

```bash
# Lint your PolicyDomain
mpe lint -f my-domain.yml

# Run policy tests
echo {} | mpe test decision -b my-domain.yml
```

## Use Cases

- **API Gateway Authorization** - Protect microservices with centralized policy decisions
- **Data Access Governance** - Control who can access sensitive data and under what conditions
- **Service Mesh Integration** - Works with Envoy and other service mesh sidecars
- **Compliance Enforcement** - Implement GDPR, HIPAA, and SOX access controls

## Documentation

For comprehensive documentation, tutorials, and API reference, visit:

**[https://manetu.github.io/policyengine](https://manetu.github.io/policyengine)**

- [Introduction](https://manetu.github.io/policyengine/) - What MPE is and what it offers
- [How It Works](https://manetu.github.io/policyengine/how-it-works) - Architecture overview (PDP, PEP, PORC)
- [Getting Started](https://manetu.github.io/policyengine/getting-started) - Installation and setup
- [Quick Start](https://manetu.github.io/policyengine/quick-start) - Create your first PolicyDomain
- [Concepts](https://manetu.github.io/policyengine/concepts) - PBAC, PolicyDomains, and core concepts
- [Integration](https://manetu.github.io/policyengine/integration) - Embed the Go library or use the HTTP API
- [CLI Reference](https://manetu.github.io/policyengine/reference/cli) - Command-line tool documentation

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

See [LICENSE](LICENSE) for details.
