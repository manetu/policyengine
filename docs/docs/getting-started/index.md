---
sidebar_position: 1
---

# Getting Started

This section will help you set up your development environment and get ready to work with the Manetu PolicyEngine.

## Overview

The Manetu PolicyEngine provides:

1. **A Go library** (`github.com/manetu/policyengine`) for embedding policy evaluation in your applications
2. **A CLI tool** (`mpe`) for developing, testing, and serving policies
3. **A [PolicyDomain](/concepts/policy-domains) schema** for organizing policies into deployable bundles

## What You'll Learn

In this section, you'll learn how to:

- Install the required prerequisites
- Install the `mpe` CLI
- Verify your installation

## Quick Install

The fastest way to install on macOS or Linux is via Homebrew:

```bash
brew tap manetu/tap
brew install mpe
```

Alternatively, if you have Go installed:

```bash
go install github.com/manetu/policyengine/cmd/mpe@latest
```

Then verify the installation:

```bash
mpe --help
```

For detailed installation instructions, see the following pages.
