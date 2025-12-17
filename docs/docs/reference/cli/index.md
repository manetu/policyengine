---
sidebar_position: 1
---

# CLI Reference

The `mpe` CLI provides tools for developing, testing, and serving policies.

## Installation

```bash
# From source
git clone https://github.com/manetu/policyengine.git
cd policyengine
make build

# Using go install
go install github.com/manetu/policyengine/cmd/mpe@latest
```

## Global Options

```
--trace, -t    Enable OPA trace logging output (default: false)
--help, -h     Show help
```

## Commands

| Command | Description |
|---------|-------------|
| <IconText icon="build">[`build`](/reference/cli/build)</IconText> | Build PolicyDomain from PolicyDomainReference |
| <IconText icon="lint">[`lint`](/reference/cli/lint)</IconText> | Validate YAML and lint Rego code |
| <IconText icon="test">[`test`](/reference/cli/test)</IconText> | Test policy decisions and mappers |
| <IconText icon="serve">[`serve`](/reference/cli/serve)</IconText> | Run a policy decision point server |
| <IconText icon="version">[`version`](/reference/cli/version)</IconText> | Print the version of mpe |

## Quick Examples

### Lint a PolicyDomain

```bash
mpe lint -f my-domain.yml
```

### Build from Reference

```bash
mpe build -f my-domain-ref.yml -o my-domain.yml
```

### Test a Decision

```bash
mpe test decision -b my-domain.yml -i input.json
```

### Run a Server

```bash
mpe serve -b my-domain.yml --port 9000
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MPE_CLI_OPA_FLAGS` | Additional OPA flags | `--v0-compatible` |
| `MPE_LOG_LEVEL` | Logging level | `info` |
| `MPE_LOG_FORMATTER` | Log format (`json` or `text`) | `json` |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (validation failed, file not found, etc.) |
