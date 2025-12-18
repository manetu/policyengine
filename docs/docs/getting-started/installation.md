---
sidebar_position: 3
---

# Installation

This guide covers installing the `mpe` CLI and the Go library.

## Installing the CLI

### Using Homebrew (macOS/Linux)

The easiest way to install `mpe` on macOS or Linux is via Homebrew using our custom tap:

```bash
brew tap manetu/tap
brew install mpe
```

To upgrade to the latest version:

```bash
brew upgrade mpe
```

### From Source

Clone the repository and build:

```bash
git clone https://github.com/manetu/policyengine.git
cd policyengine
make build
```

The binary will be created at `target/mpe`. Add it to your PATH:

```bash
# Add to your shell profile (.bashrc, .zshrc, etc.)
export PATH=$PATH:/path/to/policyengine/target
```

### Using Go Install

If you have Go installed, you can install directly:

```bash
go install github.com/manetu/policyengine/cmd/mpe@latest
```

## Verifying Installation

After installation, verify the CLI is working:

```bash
mpe --help
```

You should see output like:

```
NAME:
   mpe - A CLI application for working with the Manetu PolicyEngine

USAGE:
   mpe [global options] [command [command options]]

COMMANDS:
   test     Invokes various aspects of policy-decision flow, simplifying policy-domain authoring and verification
   serve    Creates a decision-point service
   lint     Validate PolicyDomain YAML files for syntax errors and lint embedded Rego code
   build    Build PolicyDomain YAML from PolicyDomainReference (with external .rego files)
   version  Print the version of mpe
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --trace, -t  Enable OPA trace logging output to stderr for commands that evaluate REGO
   --help, -h   show help
```

## Installing the Go Library

To use the PolicyEngine in your Go application:

```bash
go get github.com/manetu/policyengine@latest
```

Then import into your code:

```go
import (
    "github.com/manetu/policyengine/pkg/core"
    "github.com/manetu/policyengine/pkg/core/options"
)
```

## Development Setup

If you want to contribute to the PolicyEngine:

```bash
# Clone the repository
git clone https://github.com/manetu/policyengine.git
cd policyengine

# Install dependencies
go mod download

# Run tests
make test

# Run all checks (lint, test, static analysis)
make all
```

## Next Steps

Now that you have the CLI installed, proceed to:

- [Quick Start](/quick-start) - Create your first PolicyDomain
- [CLI Reference](/reference/cli) - Learn all CLI commands

