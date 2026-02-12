---
sidebar_position: 3
---

# mpe lint

Validate PolicyDomain YAML files for syntax errors and lint embedded Rego code.

## Synopsis

```bash
mpe lint --file <file> [--opa-flags <flags>] [--no-opa-flags] [--regal]
```

## Description

The `lint` command performs comprehensive validation of PolicyDomain YAML files. It operates in two modes:

### Standard Mode (default)

Runs the full validation pipeline:

1. **YAML validation**: Checks for valid YAML syntax
2. **Rego compilation**: Compiles all embedded Rego code
3. **Dependency resolution**: Validates cross-references between policies and libraries
4. **OPA check**: Runs `opa check` for additional linting

### Regal Mode (`--regal`)

Runs [Regal](https://docs.styra.com/regal) linting **instead of** the standard validation pipeline. Regal is OPA's official linter for Rego code and checks for style issues, best practices, and potential bugs.

- Extracts all embedded Rego from policies, policy-libraries, and mappers
- Runs Regal's full rule set against each Rego module
- No separate installation required — Regal is bundled into `mpe`

## Options

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--file` | `-f` | PolicyDomain YAML file(s) to lint | Yes |
| `--opa-flags` | | Additional flags for `opa check` | No |
| `--no-opa-flags` | | Disable all OPA flags | No |
| `--regal` | | Run Regal linting instead of standard validation | No |

## Examples

### Lint a Single File

```bash
mpe lint -f my-domain.yml
```

### Lint Multiple Files

```bash
mpe lint -f domain1.yml -f domain2.yml
```

### With Custom OPA Flags

```bash
mpe lint -f my-domain.yml --opa-flags "--strict"
```

### Without OPA Flags

```bash
mpe lint -f my-domain.yml --no-opa-flags
```

### Regal Linting

```bash
mpe lint -f my-domain.yml --regal
```

### Regal Linting Multiple Files

```bash
mpe lint -f domain1.yml -f domain2.yml --regal
```

## Output

### Success (Standard Mode)

```
Linting YAML files...

✓ my-domain.yml: Valid YAML
✓ my-domain.yml: Valid Rego in library 'utils'
✓ my-domain.yml: Valid Rego in policy 'main'
✓ my-domain.yml: Valid Rego in policy 'admin'
✓ my-domain.yml: Valid Rego in mapper 'http-mapper'
---
All checks passed: 1 file(s) validated successfully
```

### YAML Error

```
Linting YAML files...

✗ my-domain.yml (YAML)
  Error: yaml: line 15: found character that cannot start any token
```

### Rego Error

```
Linting YAML files...

✓ my-domain.yml: Valid YAML
✗ my-domain.yml (Rego in policy 'main')
  Error: 1 error occurred: policy.rego:5: rego_parse_error: unexpected token
```

### Dependency Error

```
Linting YAML files...

✓ my-domain.yml: Valid YAML
✗ my-domain.yml (Reference error: library 'unknown-lib' not found)
```

### Success (Regal Mode)

```
Running Regal linting...

---
Regal linting passed: 1 file(s) validated successfully
```

### Regal Violations

```
Running Regal linting...

✗ my-domain.yml (Regal: use-assignment-operator in policy 'main' at line 12)
✗ my-domain.yml (Regal: no-whitespace-comment in library 'utils' at line 5)
---
Regal linting completed: 2 violation(s)
```

## Auto-Build

The lint command automatically builds `PolicyDomainReference` files before linting:

```bash
# If my-domain.yml is a PolicyDomainReference, it will be built first
mpe lint -f my-domain-ref.yml
```

## OPA Flags

Default OPA flags: `--v0-compatible`

Override via:
- Command line: `--opa-flags "--strict --v1-compatible"`
- Environment variable: `MPE_CLI_OPA_FLAGS="--strict"`
- Disable: `--no-opa-flags`

## Validation Checks

### Standard Mode

| Check | Description |
|-------|-------------|
| YAML syntax | Valid YAML format |
| Rego syntax | Parseable Rego code |
| Rego compilation | Code compiles without errors |
| Package declaration | Each policy has `package authz` |
| Dependency resolution | All dependencies exist |
| Cross-domain references | External references are valid |
| OPA check | Additional OPA linting rules |

### Regal Mode

| Check | Description |
|-------|-------------|
| Regal rules | Style, best practices, and bug detection via Regal's built-in rule set |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | All files valid |
| 1 | One or more files have errors |

## Best Practices

1. **Run early and often**: Lint during development
2. **CI integration**: Add to your CI pipeline
3. **Pre-commit hook**: Lint before commits
4. **Fix all warnings**: Keep code clean
