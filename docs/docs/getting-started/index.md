---
sidebar_position: 1
---

# Getting Started

This section will help you set up your development environment and get ready to work with the Manetu PolicyEngine.

## Overview

The Manetu PolicyEngine provides:

1. **A [CLI tool](/reference/cli)** (`mpe`) for developing, testing, and serving policies
2. **A [PolicyDomain](/concepts/policy-domains) schema** for organizing policies into deployable bundles
3. **An [HTTP API](/integration/http-api)** for integrating with applications in any language
4. **An [embedded Go library](/integration/go-library)** for Go applications needing lowest latency <FeatureChip variant="oss" label="OSS Only"/>

:::note Use MPE with Any Language
MPE is written in Go, but you don't need Go to use it. Install `mpe` via Homebrew (or download a binary), author your policies, and integrate via the HTTP API from Python, Java, TypeScript, or any other language. Go is only required if you want to build `mpe` from source or use the embedded library.
:::

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

Then verify the installation:

```bash
mpe --help
```

**Alternative install methods:**

- **From source (requires Go 1.21+):** `go install github.com/manetu/policyengine/cmd/mpe@latest`
- **Binary download:** See [releases](https://github.com/manetu/policyengine/releases)

For detailed installation instructions, see the following pages.
