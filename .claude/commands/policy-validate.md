---
description: Validate PolicyDomain YAML files and Rego code
argument-hint: "[path]"
---

# Policy Validation Agent

Validates PolicyDomain YAML files and Rego code for correctness and best practices.

## Instructions

You are the Policy Validation Agent for the Manetu PolicyEngine project. Your job is to validate PolicyDomain YAML files and embedded Rego policies.

### When invoked without arguments:

1. Find all PolicyDomain YAML files in the project:
   - Check `docs/static/examples/*/policydomain.yml`
   - Check `testdata/**/*.yaml` and `testdata/**/*.yml`
   - Check any other `.yaml` or `.yml` files that contain `apiVersion: manetu.io/v1`

2. Run `./bin/mpe lint` on each PolicyDomain file found

3. Report results in a structured format:
   - List files that passed validation
   - List files with errors, including specific error messages
   - Provide suggestions for fixing common issues

### When invoked with a path argument:

1. Validate the specified file or directory
2. If a directory, find all PolicyDomain files within it
3. Run `./bin/mpe lint` on each file
4. Report detailed results

### Common Issues to Check:

1. **YAML Syntax Errors**: Invalid YAML structure
2. **Schema Violations**: Missing required fields, invalid field types
3. **Rego Syntax Errors**: Invalid Rego code in policies or mappers
4. **Reference Errors**: References to undefined roles, scopes, or resources
5. **MRN Format**: Invalid Manetu Resource Name patterns
6. **Duplicate Definitions**: Duplicate names for roles, operations, etc.

### Output Format:

```
## Policy Validation Report

### Summary
- Files scanned: X
- Passed: Y
- Failed: Z

### Results

#### Passed
- path/to/file1.yml
- path/to/file2.yml

#### Failed
- path/to/file3.yml
  - Error: [error message]
  - Suggestion: [how to fix]

### Recommendations
[Any general recommendations based on patterns found]
```

### Commands to Use:

```bash
# Build mpe if needed
make build

# Lint a PolicyDomain file
./bin/mpe lint -f <path-to-policydomain.yml>

# Find PolicyDomain files
find . -name "policydomain.yml" -o -name "policydomain.yaml"
```
