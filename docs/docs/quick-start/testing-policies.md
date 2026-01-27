---
sidebar_position: 3
---

# Testing Policies

Now that you've created your first PolicyDomain, let's verify it works correctly using `mpe test decision`.

## Your First Test

Create a test input file with a [PORC expression](/concepts/porc) that matches your PolicyDomain:

```bash
cat > test-input.json << 'EOF'
{
  "principal": {
    "sub": "user123",
    "mroles": ["mrn:iam:role:admin"]
  },
  "operation": "api:resource:read",
  "resource": {
    "id": "mrn:app:resource:123",
    "group": "mrn:iam:resource-group:default"
  },
  "context": {}
}
EOF
```

Run the test:

```bash
mpe test decision -b my-domain.yml -i test-input.json
```

## Understanding the Result

The output is an **AccessRecord**—a JSON document capturing the evaluation. The key field is `decision`:

```bash
# Extract just the decision
mpe test decision -b my-domain.yml -i test-input.json | jq .decision
# Output: "GRANT" or "DENY"
```

For human-readable output during debugging, add `--pretty-log`:

```bash
mpe test decision -b my-domain.yml -i test-input.json --pretty-log
```

## Verifying Your PolicyDomain

Test a few scenarios to verify your policies work as expected:

1. **Authenticated user with correct role** → should be <DecisionChip decision="grant" />
2. **Missing principal** → should be <DecisionChip decision="deny" />
3. **Wrong role for the operation** → should be <DecisionChip decision="deny" />

If a test produces unexpected results, use `--trace` to see the evaluation steps:

```bash
mpe --trace test decision -b my-domain.yml -i test-input.json
```

## Next Steps

- [Testing Policies Guide](/guides/testing-policies) — Comprehensive testing guide covering mappers, Envoy pipeline, common patterns, and best practices
- [CLI Reference: mpe test](/reference/cli/test) — Complete command reference
- [Reading Access Records](/guides/reading-access-records) — How to interpret test output in detail
