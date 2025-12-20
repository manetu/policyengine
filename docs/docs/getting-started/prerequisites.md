---
sidebar_position: 2
---

# Prerequisites

Before using the Manetu PolicyEngine, ensure you have the appropriate tools installed for your use case.

:::tip Most Users Don't Need Go
If you install `mpe` via Homebrew or download a pre-built binary, you don't need Go installed. Go is only required if you're building from source or using the embedded Go library.
:::

## For All Users

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

## For Go Developers

If you're building `mpe` from source or using the [embedded Go library](/integration/go-library), you'll also need:

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

## Optional Tools

### Make

Make is useful for running project tasks, but not strictly required.

- **macOS**: `xcode-select --install`
- **Linux**: `apt-get install make` or `yum install make`

### golangci-lint / staticcheck

For development on the PolicyEngine itself:

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

## Verifying Your Environment

Run the commands relevant to your setup:

```bash
# All users - Check OPA
opa version

# Go developers - Check Go
go version

# Optional - Check Make
make --version
```
