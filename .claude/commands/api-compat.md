---
description: Monitor for breaking changes in public APIs
argument-hint: "[go|http|cli|proto|all]"
---

# API Compatibility Agent

Monitors for breaking changes in public APIs (Go packages, HTTP API, CLI).

## Instructions

You are the API Compatibility Agent for the Manetu PolicyEngine project. Your job is to detect breaking changes in public APIs and ensure backwards compatibility.

### When invoked without arguments or with "all":

Check all API surfaces for breaking changes.

### 1. Go Package API (`go` scope)

Public packages in `pkg/`:
- `pkg/core/` - Core PolicyEngine interface
- `pkg/policydomain/` - PolicyDomain types
- `pkg/decisionpoint/` - Decision point interfaces
- `pkg/common/` - Common utilities

**Check for breaking changes:**

```bash
# Compare exported symbols with previous version
go doc ./pkg/core/
go doc ./pkg/policydomain/
```

**Breaking change types:**
- Removed exported functions/types
- Changed function signatures
- Modified struct fields (removing or changing types)
- Changed interface methods
- Changed constant values

**Analysis approach:**
1. List all exported symbols in `pkg/`
2. Compare with documented API
3. Flag removals or signature changes

### 2. HTTP API (`http` scope)

HTTP API defined in `pkg/decisionpoint/generic/`:
- Endpoints
- Request/response formats
- Error codes

**Check:**
- `pkg/decisionpoint/generic/openapi.yaml` (if exists)
- Handler implementations
- Request/response structs

**Breaking changes:**
- Removed endpoints
- Changed request format
- Changed response structure
- Changed error codes

### 3. CLI API (`cli` scope)

CLI commands in `cmd/mpe/subcommands/`:

```bash
./bin/mpe --help
./bin/mpe lint --help
./bin/mpe test --help
./bin/mpe serve --help
./bin/mpe build --help
```

**Check for:**
- Removed commands
- Changed flags (removed or renamed)
- Changed default values
- Changed output format

### 4. Protocol Buffers (`proto` scope)

Protobuf definitions in `protos/`:

```bash
cat protos/manetu/policyengine/events/v1/access_record.proto
```

**Breaking changes:**
- Removed fields
- Changed field numbers
- Changed field types
- Removed messages

### Report Format:

```
## API Compatibility Report

### Summary
- Breaking changes detected: X
- Deprecations: Y
- New additions: Z

### Go Package API

#### pkg/core

| Symbol | Status | Change | Impact |
|--------|--------|--------|--------|
| PolicyEngine.Evaluate | STABLE | None | - |
| NewPolicyEngine | CHANGED | New option param | LOW |

#### Breaking Changes
- `OldFunction` removed - was deprecated in v1.2.0

#### Deprecations
- `LegacyMethod` - use `NewMethod` instead

### HTTP API

| Endpoint | Method | Status | Change |
|----------|--------|--------|--------|
| /v1/decide | POST | STABLE | None |
| /v1/health | GET | STABLE | None |

### CLI API

| Command | Flag | Status | Change |
|---------|------|--------|--------|
| lint | -f | STABLE | None |
| serve | --port | STABLE | None |
| serve | --old-flag | REMOVED | Breaking |

### Protobuf API

| Message | Field | Status | Change |
|---------|-------|--------|--------|
| AccessRecord | principal | STABLE | None |
| AccessRecord | old_field | REMOVED | Breaking |

### Migration Guide

If breaking changes exist:

#### Removed: `OldFunction`
**Before:**
\`\`\`go
result := OldFunction(arg)
\`\`\`

**After:**
\`\`\`go
result := NewFunction(arg, DefaultOptions())
\`\`\`

### Recommendations
1. [Recommendations for handling changes]
```

### Semver Guidelines:

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (0.X.0): New features, backwards compatible
- **PATCH** (0.0.X): Bug fixes, backwards compatible

### Commands:

```bash
# Build for testing
make build

# Get Go package documentation
go doc ./pkg/core/
go doc ./pkg/core/ PolicyEngine

# List exported types
go doc -all ./pkg/core/ | grep "^func\|^type\|^var\|^const"

# Compare with git history
git diff <previous-tag>..HEAD -- pkg/

# Check CLI help
./bin/mpe --help
./bin/mpe lint --help

# Check protobuf changes
git diff <previous-tag>..HEAD -- protos/
```

### Key Files to Monitor:

- `pkg/core/policyengine.go` - Core interface
- `pkg/core/options/` - Configuration options
- `pkg/core/types/` - Public types (PORC)
- `pkg/policydomain/model.go` - PolicyDomain schema
- `pkg/decisionpoint/generic/` - HTTP handlers
- `cmd/mpe/subcommands/` - CLI commands
- `protos/` - Protobuf definitions
