---
slug: /
sidebar_position: 1
---

import useBaseUrl from '@docusaurus/useBaseUrl';

# Introduction

<img src={useBaseUrl('/img/mpe-logo.svg')} alt="Manetu PolicyEngine Logo" style={{float: 'right', height: '125px', marginLeft: '20px', marginBottom: '10px'}} />

The Manetu PolicyEngine (MPE) is a programming language agnostic access-control and governance layer that organizations use to protect software assets such as Application Programming Interfaces (APIs) and sensitive data using a [Policy-Based Access Control (PBAC)](/concepts/pbac) model.

<div class="centered-image">
![Authorization Challenges](./assets/challenges.svg)
</div>

As a core component of the Manetu governance platform, MPE provides the policy evaluation engine that enables fine-grained, context-aware access control across data, APIs, and services. It features a high-performance, flexible architecture with comprehensive tooling for policy development and testing.

## Community and Premium Editions

The Manetu PolicyEngine is available in two editions:

- <FeatureChip variant="community" label="Community Edition" size="medium"/> — (this project) A fully functional policy engine that you can embed in your applications or run as a standalone service. It provides everything you need to author, test, and enforce policies.

- <FeatureChip variant="premium" label="Premium Edition" size="medium"/> — Commercial enhancements available through a licensing arrangement with Manetu. Premium builds on the Community foundation to add enterprise-grade capabilities for organizations with advanced governance, observability, and operational requirements.

### Feature Comparison

| Feature                                                                                           | <FeatureChip variant="community" label="Community" /> | <FeatureChip variant="premium" label="Premium" />  |
|---------------------------------------------------------------------------------------------------|:-----------------------------------------------------:|:--------------------------------------------------:|
| <TableSection><IconText icon="settings">**Core Policy Engine**</IconText></TableSection>          |                                                       |                                                    |
| OPA/Rego policy evaluation                                                                        |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| PolicyDomain model (policies, roles, groups, scopes)                                              |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Multi-phase policy evaluation                                                                     |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Local resource resolution via selectors                                                           |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Decision Replay                                                                                   |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Istio/Envoy Integration                                                                           |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| <TableSection><IconText icon="terminal">**Developer Tooling**</IconText></TableSection>           |                                                       |                                                    |
| CLI for build, lint, and test                                                                     |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Local development server (`mpe serve`)                                                            |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| <TableSection><IconText icon="extension">**Integration**</IconText></TableSection>                |                                                       |                                                    |
| Embeddable Go library                                                                             |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="no" />            |
| HTTP decision service                                                                             |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| <TableSection><IconText icon="architecture">**Architecture & Platform**</IconText></TableSection> |                                                       |                                                    |
| Stateless, horizontally scalable PDPs                                                             |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Flexible deployment: embedded, sidecar, or standalone                                             |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Multi-architecture support (amd64, arm64)                                                         |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| Update policies without application restart (static reload)                                       |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| GitOps compatible policy updates                                                                  |            <FeatureCheck variant="yes" />             |           <FeatureCheck variant="yes" />           |
| <TableSection><IconText icon="business">**Enterprise Features**</IconText></TableSection>         |                                                       |                                                    |
| Update policies without PDP restart                                                               |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Kubernetes Operator with auto-scaling sidecars                                                    |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Centralized policy administration                                                                 |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| ElasticSearch integration for audit storage, indexing, and reporting                              |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Queryable Audit History                                                                           |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Analytics Dashboards                                                                              |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Streaming Live Audit                                                                              |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| Visual Policy Replay+Debugger                                                                     |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |
| External resource resolution integration (CMDBs, APIs, etc)                                       |             <FeatureCheck variant="no" />             |           <FeatureCheck variant="yes" />           |

:::info
The Premium Edition requires integration via the HTTP interface to enable enterprise features such as centralized audit and policy coordination. The embeddable Go library is available only in the Community Edition.
:::

Interested in Premium features? Contact [Manetu](https://manetu.com) to learn more.

## Who This Documentation Is For

- **Developers** who need to integrate the Manetu PolicyEngine into their applications
- **Policy Authors** who need to develop policies for applications protected by the Manetu PolicyEngine
- **DevOps Engineers** who need to deploy and manage policy decision points

## Key Features

<SectionHeader icon="security" level={3}>Least Privilege by Design</SectionHeader>

The PolicyEngine is architected to make the [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege) practical at scale:

- <IconText icon="block">**Default DENY**</IconText>: Access is denied unless explicitly granted—new principals start with zero permissions
- <IconText icon="visibility">**Observable Decisions**</IconText>: Every authorization decision generates an [AccessRecord](/concepts/audit) with full context
- <IconText icon="replay">**Policy Replay**</IconText>: Test policy changes against real traffic before deploying
- <IconText icon="trending">**Evidence-Based Refinement**</IconText>: Start with strict policies and iteratively expand access based on observed needs, not guesswork

This observable architecture transforms access control from a guessing game into an evidence-based practice. Rather than granting broad permissions "just in case," you can safely start restrictive and expand access precisely where it's demonstrated necessary. See [Audit & Access Records](/concepts/audit) for details on the iterative refinement workflow.

<SectionHeader icon="integration" level={3}>Open Policy Agent Integration</SectionHeader>

The Manetu PolicyEngine is built on [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), an open-source engine for executing policy statements. You can use the rich ecosystem for designing and debugging policy expressions in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language to precisely control access to your resources.

<SectionHeader icon="layers" level={3}>PolicyDomain Model</SectionHeader>

Policies are organized into **[PolicyDomains](/concepts/policy-domains)** - self-contained bundles that define:

- <IconText icon="gavel">**[Policies](/concepts/policies)**</IconText>: Rego code that makes access control decisions
- <IconText icon="library">**[Policy Libraries](/concepts/policy-libraries)**</IconText>: Reusable Rego code shared across policies
- <IconText icon="badge">**[Roles](/concepts/roles)**</IconText>: Named policy assignments for identity-based access
- <IconText icon="group">**[Groups](/concepts/groups)**</IconText>: Collections of roles for organizational structure
- <IconText icon="folder">**[Resource Groups](/concepts/resource-groups)**</IconText>: Policy assignments for resource-based access
- <IconText icon="inventory">**[Resources](/concepts/resources)**</IconText>: Selector-based routing of resources to groups (v1alpha4+)
- <IconText icon="tune">**[Scopes](/concepts/scopes)**</IconText>: OAuth-style permission boundaries
- <IconText icon="play">**[Operations](/concepts/operations)**</IconText>: Route requests to appropriate policies
- <IconText icon="transform">**[Mappers](/concepts/mappers)**</IconText>: Transform external inputs (like Envoy requests) into [PORC](/concepts/porc) expressions

<SectionHeader icon="terminal" level={3}>Developer-Friendly Tooling</SectionHeader>

The `mpe` CLI provides comprehensive tooling for the policy development lifecycle:

- <IconText icon="build">**`mpe build`**</IconText>: Compile PolicyDomain definitions from external Rego files
- <IconText icon="lint">**`mpe lint`**</IconText>: Validate YAML syntax and lint embedded Rego code
- <IconText icon="test">**`mpe test`**</IconText>: Test policy decisions with various inputs
- <IconText icon="serve">**`mpe serve`**</IconText>: Run a local policy decision point for development

Advanced debugging capabilities include `--trace` mode for line-by-line policy evaluation tracing. The Premium Edition adds decision replay with visual code coverage, benchmarking, and historical analysis.

<SectionHeader icon="architecture" level={3}>Cloud-Native Architecture</SectionHeader>

MPE is built for modern, web-scale microservice architectures:

- <IconText icon="language">**Language Agnostic**</IconText>: Protect resources consistently across services written in any language—Go, Python, Java, TypeScript, Rust, and more—using a unified HTTP API
- <IconText icon="scale">**Horizontally Scalable**</IconText>: Stateless PDPs scale out effortlessly to meet any performance or availability requirements
- <IconText icon="deployment">**Flexible Deployment**</IconText>: Run the PDP embedded in your application, as a 1:1 sidecar, or as a shared standalone service
- <IconText icon="update">**Decoupled Updates**</IconText>: Update policies independently without recompiling or redeploying your applications
- <IconText icon="platform">**Multi-Architecture**</IconText>: Native support for both amd64 and arm64 infrastructure

## Next Steps

- <IconText icon="settings">[How It Works](/how-it-works)</IconText> - Understand the architecture before diving in
- <IconText icon="rocket">[Getting Started](/getting-started)</IconText> - Set up your development environment
- <IconText icon="flash">[Quick Start](/quick-start)</IconText> - Create your first PolicyDomain
- <IconText icon="school">[Concepts](/concepts)</IconText> - Understand core concepts in depth
- <IconText icon="extension">[Integration](/integration)</IconText> - Integrate the PolicyEngine into your application
- <IconText icon="book">[Reference](/reference/cli)</IconText> - Complete CLI and schema reference
