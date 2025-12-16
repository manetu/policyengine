---
sidebar_position: 2
---

# mpe build

Build a PolicyDomain from a PolicyDomainReference with external Rego files.

## Synopsis

```bash
mpe build --file <file> [--output <file>]
```

## Description

The `build` command transforms a `PolicyDomainReference` YAML file into a complete `PolicyDomain` by reading external `.rego` files and inlining their contents.

This allows you to:
- Keep Rego code in separate `.rego` files for better editor support
- Use version control effectively on Rego files
- Maintain cleaner YAML files

## Options

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--file` | `-f` | PolicyDomainReference YAML file(s) to build | Yes |
| `--output` | `-o` | Output file path (single file only) | No |

## Examples

### Build a Single File

```bash
mpe build -f my-domain-ref.yml
# Creates: my-domain-ref-built.yml
```

### Build with Custom Output

```bash
mpe build -f my-domain-ref.yml -o my-domain.yml
```

### Build Multiple Files

```bash
mpe build -f domain1-ref.yml -f domain2-ref.yml
# Creates: domain1-ref-built.yml, domain2-ref-built.yml
```

## PolicyDomainReference Format

A `PolicyDomainReference` uses `rego_filename` instead of inline `rego`:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomainReference
metadata:
  name: my-domain
spec:
  policy-libraries:
    - mrn: "mrn:iam:library:utils"
      name: utils
      rego_filename: lib/utils.rego

  policies:
    - mrn: "mrn:iam:policy:main"
      name: main
      dependencies:
        - "mrn:iam:library:utils"
      rego_filename: policies/main.rego

  mappers:
    - name: http-mapper
      selector:
        - ".*"
      rego_filename: mappers/http.rego
```

## Output Format

The build process:

1. Reads the `PolicyDomainReference`
2. For each `rego_filename`, reads the file content
3. Replaces `rego_filename` with `rego` containing the file content
4. Changes `kind` from `PolicyDomainReference` to `PolicyDomain`
5. Writes the result

### Before (Reference)

```yaml
policies:
  - mrn: "mrn:iam:policy:main"
    name: main
    rego_filename: policies/main.rego
```

### After (Built)

```yaml
policies:
  - mrn: "mrn:iam:policy:main"
    name: main
    rego: |
      package authz
      default allow = false
      # ... rest of main.rego content
```

## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| File not found | `rego_filename` path doesn't exist | Check file path is correct |
| Both specified | `rego` and `rego_filename` both present | Use only one |
| Invalid YAML | Malformed YAML syntax | Fix YAML syntax errors |

## Best Practices

1. **Use relative paths**: Keep `.rego` files relative to the YAML file
2. **Organize by type**: Separate directories for policies, libraries, mappers
3. **Version control**: Commit both reference and built files
4. **CI integration**: Build as part of your CI pipeline

## Project Structure Example

```
my-policy-domain/
├── domain-ref.yml          # PolicyDomainReference
├── domain.yml              # Built PolicyDomain (generated)
├── lib/
│   ├── utils.rego
│   └── helpers.rego
├── policies/
│   ├── main.rego
│   └── admin.rego
└── mappers/
    └── http.rego
```
