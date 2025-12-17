---
sidebar_position: 2
---

# How It Works

Before diving into installation and policy authoring, it helps to understand how the Manetu PolicyEngine fits into your application architecture. This page explains the core concepts you'll encounter throughout the documentation.

## The Big Picture

The Manetu PolicyEngine is an **authorization service**—it answers the question "Is this action allowed?" Your application asks, the PolicyEngine answers.

```mermaid
flowchart LR
    App["Your Application"]
    PE["PolicyEngine"]
    Decision["GRANT or DENY"]

    App -->|"Can Alice read document X?"| PE
    PE --> Decision

    style App fill:#1a145f,stroke:#03a3ed,color:#fff
    style PE fill:#03a3ed,stroke:#0282bd,color:#fff
    style Decision fill:#38a169,stroke:#2f855a,color:#fff
```

This separation is powerful: your application handles business logic while the PolicyEngine handles access control. Policies can be updated without changing application code.

## Key Concepts

### Policy Decision Point (PDP)

The **PDP** is the PolicyEngine itself. It:
- Receives authorization requests
- Evaluates them against policies
- Returns GRANT or DENY decisions
- Emits an [AccessRecord](/concepts/audit) for every decision

The PDP is stateless—it doesn't know your application's business logic. It only knows the policies you've defined and the information you send with each request.

Every decision generates a normalized **AccessRecord** that captures the complete evaluation context: the input PORC, the final decision, and details about each policy evaluated. This audit trail enables compliance reporting, anomaly detection, and forensic analysis. See [Audit & Access Records](/concepts/audit) for details.

### Policy Enforcement Point (PEP)

A **PEP** is code in your application that enforces access control. You create PEPs wherever you need to protect something. Each PEP:

1. **Gathers context** about the current request (who's asking, what they want, what resource is involved)
2. **Calls the PDP** with that context
3. **Enforces the decision** (proceeds if GRANT, blocks if DENY)

```mermaid
flowchart TB
    subgraph APP["Your Application"]
        PEP1["PEP: API Gateway"]
        PEP2["PEP: Data Layer"]
        PEP3["PEP: Admin Panel"]
    end

    PEP1 & PEP2 & PEP3 -->|Authorization Request| PDP["PolicyEngine (PDP)"]
    PDP --> Decision["GRANT / DENY"]

    style APP fill:transparent,stroke:#03a3ed,stroke-width:2px
    style PEP1 fill:#1a145f,stroke:#03a3ed,color:#fff
    style PEP2 fill:#1a145f,stroke:#03a3ed,color:#fff
    style PEP3 fill:#1a145f,stroke:#03a3ed,color:#fff
    style PDP fill:#03a3ed,stroke:#0282bd,color:#fff
    style Decision fill:#38a169,stroke:#2f855a,color:#fff
```

You might have one PEP or dozens—wherever your application needs to make an access control decision.

### PORC: The Authorization Request Format

When a PEP calls the PDP, it sends a **[PORC expression](/concepts/porc)**—a standardized format containing everything the PolicyEngine needs to make a decision:

| Component | What It Contains | Example |
|-----------|-----------------|---------|
| **P**rincipal | Who is making the request | User identity, roles, groups |
| **O**peration | What action they want to perform | `api:documents:read` |
| **R**esource | What they want to access | Document ID, owner, classification |
| **C**ontext | Additional circumstances | Timestamp, IP address, request metadata |

```json
{
  "principal": {
    "sub": "alice@example.com",
    "mroles": ["mrn:iam:role:editor"]
  },
  "operation": "api:documents:update",
  "resource": "mrn:app:document:12345",
  "context": {
    "source_ip": "10.0.1.50"
  }
}
```

Your PEP constructs this PORC expression from whatever information is available (JWT tokens, request headers, database lookups) and sends it to the PDP.

### PolicyDomains: Where Policies Live

A **[PolicyDomain](/concepts/policy-domains)** is a bundle containing everything the PolicyEngine needs to make decisions:

- **[Policies](/concepts/policies)**: The actual rules written in Rego (OPA's policy language)
- **[Roles](/concepts/roles)**: Named collections of permissions for users
- **[Groups](/concepts/groups)**: Collections of roles for organizational structure
- **[Resource Groups](/concepts/resource-groups)**: Policy assignments for resource-based access
- **[Scopes](/concepts/scopes)**: Permission boundaries (like OAuth scopes)
- **[Operations](/concepts/operations)**: Routes requests to appropriate policies

```mermaid
flowchart LR
    subgraph PD["PolicyDomain"]
        Policies["Policies"]
        Roles["Roles"]
        Groups["Groups"]
        RG["Resource Groups"]
        Scopes["Scopes"]
        Ops["Operations"]
    end

    Request["PORC<br/>Request"]
    PDP["PolicyEngine<br/>(PDP)"]
    Decision["GRANT /<br/>DENY"]

    Request --> PDP
    PDP --> Decision
    PD -.->|load| PDP

    style PD fill:transparent,stroke:#03a3ed,stroke-width:2px,stroke-dasharray: 5 5
    style Policies fill:#1a145f,stroke:#03a3ed,color:#fff
    style Roles fill:#1a145f,stroke:#03a3ed,color:#fff
    style Groups fill:#1a145f,stroke:#03a3ed,color:#fff
    style RG fill:#1a145f,stroke:#03a3ed,color:#fff
    style Scopes fill:#1a145f,stroke:#03a3ed,color:#fff
    style Ops fill:#1a145f,stroke:#03a3ed,color:#fff
    style Request fill:#1a145f,stroke:#03a3ed,color:#fff
    style PDP fill:#03a3ed,stroke:#0282bd,color:#fff
    style Decision fill:#38a169,stroke:#2f855a,color:#fff
```

You author PolicyDomains as YAML files (with embedded or external Rego code) and load them into the PolicyEngine. The PolicyDomain is an injected configuration that defines what policies exist, how roles map to policies, and how requests are routed.

## The Development Workflow

Here's how you'll typically work with the PolicyEngine:

```mermaid
flowchart LR
    Author["1. Author<br/>PolicyDomain"]
    Test["2. Test<br/>Policies"]
    Serve["3. Serve<br/>Locally"]
    Integrate["4. Integrate<br/>with App"]
    Deploy["5. Deploy"]

    Author --> Test --> Serve --> Integrate --> Deploy

    style Author fill:#1a145f,stroke:#03a3ed,color:#fff
    style Test fill:#1a145f,stroke:#03a3ed,color:#fff
    style Serve fill:#1a145f,stroke:#03a3ed,color:#fff
    style Integrate fill:#1a145f,stroke:#03a3ed,color:#fff
    style Deploy fill:#38a169,stroke:#2f855a,color:#fff
```

1. **Author**: Write your PolicyDomain YAML with policies, roles, and other components
2. **Test**: Use `mpe test` to verify policies produce expected decisions
3. **Serve**: Run `mpe serve` to start a local PolicyEngine for development
4. **Integrate**: Add PEPs to your application that call the PolicyEngine
5. **Deploy**: Deploy your PolicyDomain and PolicyEngine to production

The `mpe` CLI tool supports each step of this workflow.

## Putting It Together

Here's the complete picture of how a request flows through the system:

```mermaid
sequenceDiagram
    participant User
    participant App as Your Application
    participant PEP as PEP (in App)
    participant PDP as PolicyEngine (PDP)
    participant PD as PolicyDomain
    participant Audit as Audit Stream

    PD-->>PDP: (loaded)

    User->>App: Request: "Update document 123"
    App->>PEP: Check authorization
    PEP->>PEP: Build PORC expression
    PEP->>PDP: Authorize(PORC)
    Note over PDP: Lookup operation policy<br/>Lookup role policies<br/>Evaluate Rego rules
    PDP->>Audit: AccessRecord
    PDP-->>PEP: GRANT
    PEP-->>App: Authorized
    App-->>User: Document updated
```

1. A user makes a request to your application
2. Your application's PEP intercepts it and builds a PORC expression
3. The PEP sends the PORC to the PolicyEngine (PDP)
4. The PDP uses its loaded PolicyDomain to look up the relevant policies and evaluate them
5. The PDP writes an AccessRecord capturing the decision and all evaluated policies
6. The PDP returns GRANT or DENY to the PEP
7. The PEP enforces the decision

:::info
The ordering of steps 5 and 6 is intentional: the audit trail is committed **before** the decision is returned. This ensures that a complete record exists before any action is taken on the outcome.
:::

## What You'll Learn Next

Now that you understand how the pieces fit together:

- **[Getting Started](/getting-started)** — Install the `mpe` CLI tool
- **[Quick Start](/quick-start)** — Create your first PolicyDomain and test it
- **[Integration](/integration)** — Build PEPs in your application

The rest of the documentation dives deeper into each component. The [Concepts](/concepts) section covers each PolicyDomain component in detail, and the [Reference](/reference/cli) provides complete CLI and schema documentation.
