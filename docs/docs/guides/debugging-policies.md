---
sidebar_position: 3
---

# Debugging Policies

This guide explains how to use OPA trace output to debug policy evaluations. When you need to understand *why* a policy granted or denied access—not just *what* the outcome was—trace output shows you the step-by-step evaluation path.

## Overview: Two Debugging Tools

PolicyEngine provides two complementary debugging tools:

| Tool | Shows | Best For |
|------|-------|----------|
| **AccessRecord** | *What* happened: which policies voted GRANT/DENY, final decision | Understanding the overall decision flow |
| **OPA Trace** | *How* each rule evaluated: variable bindings, condition checks, failures | Debugging why a specific rule matched or failed |

Use AccessRecords first to identify *which* policy caused an unexpected outcome, then use trace output to understand *why* that policy behaved as it did.

## Enabling Trace Output

Enable OPA trace logging with the `--trace` flag:

```bash
mpe --trace test decision -b my-domain.yml -i input.json
```

Combine with `--pretty-log` for easier reading of the AccessRecord:

```bash
mpe --trace --pretty-log test decision -b my-domain.yml -i input.json
```

### Filtering Trace Output

When evaluating multiple policies, trace output can be overwhelming. Use `--trace-filter` to show traces only from specific policies:

```bash
# Trace only the unix-permissions policy
mpe --trace --trace-filter "mrn:iam:policy:unix-permissions" test decision -b my-domain.yml -i input.json

# Trace multiple policies (can specify --trace-filter multiple times)
mpe --trace \
  --trace-filter "mrn:iam:policy:require-auth" \
  --trace-filter "mrn:iam:policy:unix-permissions" \
  test decision -b my-domain.yml -i input.json

# Use regex patterns to match policy families
mpe --trace --trace-filter "mrn:iam:policy:.*permissions.*" test decision -b my-domain.yml -i input.json
```

Each `--trace-filter` value is a regex pattern matched against the policy MRN. If any filter matches, that policy's evaluation will produce trace output.

:::tip
Start by identifying the problematic policy from the AccessRecord (check which policy in `references` has an unexpected decision), then use `--trace-filter` to focus on just that policy's evaluation.
:::

### Output Streams

- **Trace output** goes to stderr
- **AccessRecord** goes to stdout

This means you can redirect them separately:

```bash
# Save trace to file, view AccessRecord on terminal
mpe --trace --pretty-log test decision -b my-domain.yml -i input.json 2> trace.log

# Save AccessRecord to file, view trace on terminal
mpe --trace test decision -b my-domain.yml -i input.json > access-record.json
```

## Understanding OPA Trace Output

The trace shows every step of OPA's evaluation. Each line has this format:

```
<location>    <depth>    <operation> <expression>
```

| Column | Description |
|--------|-------------|
| **Location** | Policy MRN and line number (e.g., `mrn:iam:policy:unix-permissions:14`) |
| **Depth** | Indentation showing call depth (pipes `\|` indicate nesting) |
| **Operation** | What OPA is doing (Enter, Exit, Eval, Unify, Fail, Redo) |
| **Expression** | The Rego expression being evaluated |

### Trace Operations

| Operation | Meaning |
|-----------|---------|
| **Enter** | Starting evaluation of a rule or function |
| **Exit** | Successfully completed evaluation (produced a result) |
| **Eval** | Evaluating an expression |
| **Unify** | Binding a variable to a value |
| **Fail** | Expression evaluated to false—this path won't succeed |
| **Redo** | Backtracking to try alternative matches (common with iteration) |

### Key Patterns to Look For

**Successful evaluation path:**
```
policy:9     | Enter data.authz.allow
policy:10    | | Eval some_condition
policy:9     | | Exit data.authz.allow early
```
The `Exit` confirms the rule succeeded.

**Failed evaluation:**
```
policy:9     | Enter data.authz.allow
policy:10    | | Eval principal.sub = resource.owner
policy:10    | | Fail principal.sub = resource.owner
```
The `Fail` shows exactly which condition didn't match.

**Iteration with backtracking:**
```
library:28   | | | Eval suffix = __local20__[__local10__]
library:28   | | | Unify ":get" = suffix
library:29   | | | Eval endswith(operation, suffix)
library:29   | | | Fail endswith(operation, suffix)
library:28   | | | Redo suffix = __local20__[__local10__]
library:28   | | | Unify ":list" = suffix
```
`Redo` shows OPA trying each element in a set/array until one matches or all fail.

## Practical Examples

These examples use the [Unix Filesystem](/examples/unix-filesystem) example. Download the PolicyDomain and input files from that page to follow along, or clone the repository:

```bash
git clone https://github.com/manetu/policyengine.git
cd policyengine/docs/static/examples/unix-filesystem
```

### Example 1: Group Read Access (GRANT)

**Scenario:** Bob (in the `developers` group) reads a file shared with that group.

```bash
mpe --trace --pretty-log test decision \
  -b policydomain.yml \
  -i input-3-group-read.json
```

**Key trace excerpt** (Resource phase evaluation):

```
mrn:iam:policy:unix-permissions:14     | | Eval data.unix_perms.permission_class(...)
mrn:iam:library:unix-perms:7           | | Enter data.unix_perms.permission_class
mrn:iam:library:unix-perms:8           | | | Eval principal.sub = resource.owner
mrn:iam:library:unix-perms:8           | | | Unify "bob" = resource.owner
mrn:iam:library:unix-perms:8           | | | Unify "alice" = "bob"
mrn:iam:library:unix-perms:8           | | | Fail principal.sub = resource.owner     ← Bob isn't the owner
mrn:iam:library:unix-perms:11          | | Enter data.unix_perms.permission_class    ← Try "group" class
mrn:iam:library:unix-perms:12          | | | Eval neq(__local24__, __local25__)      ← bob != alice ✓
mrn:iam:library:unix-perms:13          | | | Eval internal.member_2(__local26__, __local27__)
mrn:iam:library:unix-perms:11          | | | Exit data.unix_perms.permission_class   ← Returns "group"
```

**What happened:**
1. The `permission_class` function first tried to match Bob as the owner → failed (Bob ≠ Alice)
2. Then tried the "group" class → succeeded (Bob is in `developers`, the file's group)
3. The permission check then verified `group.read = true`

### Example 2: Group Write Denied (DENY)

**Scenario:** Bob tries to *write* to the same file (group only has read permission).

```bash
mpe --trace --pretty-log test decision \
  -b policydomain.yml \
  -i input-4-group-write-denied.json
```

**Key trace excerpt** (the critical failure):

```
mrn:iam:policy:unix-permissions:17     | | Eval required = __local23__
mrn:iam:policy:unix-permissions:17     | | Unify required = "write"           ← Operation requires "write"
mrn:iam:policy:unix-permissions:20     | | Eval data.unix_perms.has_permission(mode, class, required)
mrn:iam:library:unix-perms:22          | | Enter data.unix_perms.has_permission
mrn:iam:library:unix-perms:22          | | | Unify "group" = class             ← Bob is in "group" class
mrn:iam:library:unix-perms:22          | | | Unify "write" = permission        ← Checking write permission
mrn:iam:library:unix-perms:23          | | | Eval mode[class][permission] = true
mrn:iam:library:unix-perms:23          | | | Unify false = true                ← group.write is false!
mrn:iam:library:unix-perms:23          | | | Fail mode[class][permission] = true
mrn:iam:policy:unix-permissions:20     | | Fail data.unix_perms.has_permission(...)
```

**What happened:**
1. Bob was classified as "group" (same as Example 1)
2. The operation `file:document:write` requires "write" permission
3. The `has_permission` check found `mode.group.write = false`
4. The main `allow` rule failed, falling through to `default allow = false`

### Example 3: Superuser Bypass (GRANT)

**Scenario:** Root writes to a locked file (no permissions for anyone).

```bash
mpe --trace --pretty-log test decision \
  -b policydomain.yml \
  -i input-7-superuser.json
```

**Key trace excerpt** (superuser rule short-circuits):

```
mrn:iam:policy:unix-permissions:24     | Enter data.authz.allow               ← Superuser rule
mrn:iam:policy:unix-permissions:25     | | Eval __local35__ = input.principal.mroles
mrn:iam:policy:unix-permissions:25     | | Unify ["mrn:iam:role:superuser"] = __local35__
mrn:iam:policy:unix-permissions:25     | | Eval internal.member_2("mrn:iam:role:superuser", __local35__)
mrn:iam:policy:unix-permissions:24     | | Exit data.authz.allow early        ← Success! No permission check needed
```

**What happened:**
1. The policy has two `allow` rules: main permission check and superuser bypass
2. OPA tried the superuser rule first (line 24)
3. Root has `mrn:iam:role:superuser` in their roles
4. The rule matched and exited early—permission bits were never checked

## Adding Custom Trace Messages

For complex debugging, add `trace()` calls to your policies:

```rego
allow if {
    trace(sprintf("Checking user %s against resource owner %s", [input.principal.sub, input.resource.owner]))
    input.principal.sub == input.resource.owner
}
```

This produces a **Note** entry in the trace:

```
policy:10    | | | Note "Checking user bob against resource owner alice"
```

:::warning Remove in Production
The `trace()` builtin adds overhead. Remove or comment out trace calls before deploying to production.
:::

## Debugging Workflow

When a policy isn't behaving as expected:

1. **Reproduce with trace enabled:**
   ```bash
   mpe --trace --pretty-log test decision -b bundle.yml -i input.json 2> trace.log
   ```

2. **Check the AccessRecord first:**
   - Which phase failed? (SYSTEM, IDENTITY, RESOURCE, SCOPE)
   - Which specific policy voted DENY?

3. **Find that policy's trace section:**
   Search for the policy MRN in the trace output (e.g., `mrn:iam:policy:unix-permissions`)

4. **Locate the failure point:**
   Search for `Fail` lines within that policy's trace

5. **Work backwards from the failure:**
   - What value was being compared?
   - What did OPA expect vs. what it found?
   - Check the `Unify` lines to see actual values

6. **Add trace() calls if needed:**
   If the built-in trace isn't clear enough, add custom trace messages

7. **Verify your fix:**
   Re-run with trace to confirm the expected path now succeeds

## Combining Trace with AccessRecords

Use both tools together for efficient debugging:

| Start With | Then Use | When |
|------------|----------|------|
| AccessRecord | Trace | You know which policy failed but not why |
| Trace | AccessRecord | You see unexpected evaluation but need the big picture |

**Example workflow:**

```bash
# Step 1: Get the high-level picture
mpe --pretty-log test decision -b bundle.yml -i input.json | jq '.references[] | select(.decision == "DENY")'

# Output shows: mrn:iam:policy:unix-permissions in RESOURCE phase

# Step 2: Drill into why that policy denied
mpe --trace test decision -b bundle.yml -i input.json 2>&1 | grep -A 20 "mrn:iam:policy:unix-permissions"
```

## Related Resources

- [Testing Policies](/guides/testing-policies) — How to run policy tests
- [Reading Access Records](/guides/reading-access-records) — Interpreting AccessRecord output
- [Policies Concept](/concepts/policies) — How policies are structured
- [CLI Reference: mpe test](/reference/cli/test) — Complete command reference
