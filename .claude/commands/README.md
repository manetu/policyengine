# PolicyEngine Management Agents

This directory contains Claude Code skills (agents) for managing the Manetu PolicyEngine project.

## Available Agents

| Agent | Command | Description |
|-------|---------|-------------|
| Policy Validation | `/policy-validate` | Validates PolicyDomain YAML files and Rego code |
| Example Guardian | `/example-guardian` | Ensures example PolicyDomains remain valid |
| Documentation Sync | `/docs-sync` | Keeps documentation synchronized with code |
| Security Auditor | `/security-audit` | Reviews policies and code for vulnerabilities |
| Test Coverage | `/test-coverage` | Monitors test coverage and identifies gaps |
| Dependency Health | `/dep-health` | Monitors dependencies for updates/vulnerabilities |
| Release Manager | `/release-manager` | Assists with release preparation and validation |
| PORC Test Generator | `/porc-test-gen` | Generates test cases for policy decisions |
| API Compatibility | `/api-compat` | Monitors for breaking changes in public APIs |
| Performance Benchmark | `/perf-bench` | Runs benchmarks and detects regressions |

## Usage

Invoke any agent using its slash command in Claude Code:

```
/policy-validate
/example-guardian multi-tenant-saas
/docs-sync check
/security-audit full
/test-coverage pkg/core
/dep-health go
/release-manager check
/porc-test-gen docs/static/examples/healthcare-hipaa/policydomain.yml
/api-compat all
/perf-bench quick
```

## Agent Details

### Policy Validation Agent (`/policy-validate`)

Validates PolicyDomain YAML files and Rego policies for correctness.

**Arguments:**
- None: Validates all PolicyDomain files in the project
- `<path>`: Validates specific file or directory

**What it checks:**
- YAML syntax and schema compliance
- Rego code compilation
- Reference resolution (roles, scopes, resources)
- MRN format validity

---

### Example Guardian Agent (`/example-guardian`)

Ensures the example PolicyDomains in `docs/static/examples/` stay valid and functional.

**Arguments:**
- None: Checks all examples
- `<example-name>`: Checks specific example (e.g., `multi-tenant-saas`)

**What it checks:**
- PolicyDomain lint status
- Test execution (if tests exist)
- Documentation alignment

---

### Documentation Sync Agent (`/docs-sync`)

Keeps documentation synchronized with code changes.

**Arguments:**
- `check` (default): Run all documentation checks
- `fix`: Attempt to auto-fix issues
- `report`: Generate comprehensive health report

**What it checks:**
- CLI documentation accuracy
- Code example validity
- Cross-reference resolution
- Stale documentation detection

---

### Security Auditor Agent (`/security-audit`)

Reviews policies and code for security vulnerabilities.

**Arguments:**
- `full` (default): Complete security audit
- `policies`: Review PolicyDomain files only
- `code`: Review Go code only
- `dependencies`: Check dependency security only

**What it checks:**
- Overly permissive policies
- Code vulnerabilities (gosec)
- Dependency CVEs
- Access control logic

---

### Test Coverage Agent (`/test-coverage`)

Monitors test coverage and identifies gaps.

**Arguments:**
- None: Full project coverage analysis
- `<package>`: Coverage for specific package

**What it provides:**
- Coverage percentages by package
- Uncovered code identification
- Missing test scenario suggestions
- Race condition detection

---

### Dependency Health Agent (`/dep-health`)

Monitors dependencies for updates and security vulnerabilities.

**Arguments:**
- `all` (default): Check both Go and npm
- `go`: Check Go dependencies only
- `npm`: Check npm dependencies only

**What it checks:**
- Outdated packages
- Security vulnerabilities
- License compliance
- Unused dependencies

---

### Release Manager Agent (`/release-manager`)

Assists with release preparation and validation.

**Arguments:**
- `check` (default): Run pre-release checks
- `prepare`: Prepare for new release
- `changelog`: Generate changelog
- `validate`: Validate release readiness

**What it provides:**
- CI status verification
- Changelog generation
- Version consistency checks
- Release checklist

---

### PORC Test Generator Agent (`/porc-test-gen`)

Generates test cases for policy decisions based on PolicyDomain definitions.

**Arguments:**
- None: Generate for all example PolicyDomains
- `<path>`: Generate for specific PolicyDomain

**What it generates:**
- Positive tests (should ALLOW)
- Negative tests (should DENY)
- Edge case tests
- Test coverage matrix

---

### API Compatibility Agent (`/api-compat`)

Monitors for breaking changes in public APIs.

**Arguments:**
- `all` (default): Check all API surfaces
- `go`: Check Go package API
- `http`: Check HTTP API
- `cli`: Check CLI interface
- `proto`: Check protobuf definitions

**What it detects:**
- Removed exports
- Changed signatures
- Breaking changes
- Deprecations

---

### Performance Benchmark Agent (`/perf-bench`)

Runs performance benchmarks and detects regressions.

**Arguments:**
- `quick` (default): Quick benchmark run
- `full`: Comprehensive benchmarks
- `compare`: Compare with baseline
- `profile`: Generate CPU/memory profiles

**What it measures:**
- Policy evaluation latency
- Memory usage
- Throughput
- Regression detection

## Adding New Commands

1. Create a new markdown file in `.claude/commands/`
2. Add YAML frontmatter with `description` and optional `argument-hint`
3. Follow the existing command format:
   - Clear usage instructions
   - Specific commands to run
   - Defined output format
   - Error handling guidance

Example frontmatter:
```yaml
---
description: Short description shown in /help
argument-hint: "[optional-arg]"
---
```
