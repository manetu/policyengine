---
sidebar_position: 3
---

# mpe lint

Validate PolicyDomain YAML files for syntax errors and lint embedded Rego code.

## Synopsis

```bash
mpe lint --file <file> [--opa-flags <flags>] [--no-opa-flags]
```

## Description

The `lint` command performs comprehensive validation:

1. **YAML validation**: Checks for valid YAML syntax
2. **Rego compilation**: Compiles all embedded Rego code
3. **Dependency resolution**: Validates cross-references between policies and libraries
4. **OPA check**: Runs `opa check` for additional linting

## Options

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--file` | `-f` | PolicyDomain YAML file(s) to lint | Yes |
| `--opa-flags` | | Additional flags for `opa check` | No |
| `--no-opa-flags` | | Disable all OPA flags | No |

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

## Output

### Success

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

| Check | Description |
|-------|-------------|
| YAML syntax | Valid YAML format |
| Rego syntax | Parseable Rego code |
| Rego compilation | Code compiles without errors |
| Package declaration | Each policy has `package authz` |
| Dependency resolution | All dependencies exist |
| Cross-domain references | External references are valid |
| OPA check | Additional OPA linting rules |

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
