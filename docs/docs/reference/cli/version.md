---
sidebar_position: 6
---

# mpe version

Print the version of the `mpe` CLI tool.

## Synopsis

```bash
mpe version
```

## Description

The `version` command displays the current version of the `mpe` CLI tool. This is useful for:

- Verifying the installed version
- Troubleshooting and bug reports
- Ensuring compatibility with PolicyDomain schemas

## Options

| Option | Alias | Description | Required |
|--------|-------|-------------|----------|
| `--help` | `-h` | Show help | No |

## Examples

### Display Version

```bash
mpe version
```

### Example Output

```
v1.2.0
```

During development, the version will display `dev`:

```
dev
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
