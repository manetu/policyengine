---
sidebar_position: 2
---

# Prerequisites

Before installing the Manetu PolicyEngine, ensure you have the following tools installed.

## Required

### Go

Go 1.21 or later is required.

**Installation:**

- **macOS**: `brew install go`
- **Linux**: Follow [Go installation instructions](https://go.dev/doc/install)
- **Windows**: Download from [go.dev/dl](https://go.dev/dl/)

Verify installation:

```bash
go version
# go version go1.21.0 darwin/arm64
```

### Open Policy Agent (OPA)

OPA is required for the `mpe lint` command to validate Rego syntax.

**Installation:**

- **macOS**: `brew install opa`
- **Linux/Windows**: Download from [OPA releases](https://github.com/open-policy-agent/opa/releases)

Verify installation:

```bash
opa version
# Version: 0.60.0
```

## Optional

### Make

Make is useful for running project tasks but not strictly required.

- **macOS**: `xcode-select --install`
- **Linux**: `apt-get install make` or `yum install make`

### golangci-lint / staticcheck

For development on the PolicyEngine itself:

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## Verifying Your Environment

Run these commands to verify all prerequisites are installed:

```bash
# Check Go
go version

# Check OPA
opa version

# Check Make (optional)
make --version
```

All commands should complete without errors.
