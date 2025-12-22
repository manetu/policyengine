---
sidebar_position: 5
---

# Resource Resolution

When a PEP submits a PORC expression for evaluation, the PolicyEngine needs to understand the resource's metadata—its group membership, classification, ownership, and annotations. There are three approaches to providing this information, and they can be used individually or in combination.

## Overview of Approaches

| Approach | Availability | How It Works |
|----------|--------------|--------------|
| [MRN String with Selector Resolution](#approach-1-mrn-string-with-selector-resolution) | All editions | PEP sends MRN string; PolicyEngine resolves metadata via regex patterns in PolicyDomain config |
| [MRN String with External Resolution](#approach-2-mrn-string-with-external-resolution) | <FeatureChip variant="premium" /> | PEP sends MRN string; PolicyEngine resolves metadata via your custom resolver integration |
| [Fully-Qualified Descriptor](#approach-3-fully-qualified-descriptor) | All editions | PEP sends complete resource metadata; no resolution needed |

:::info Combining Approaches
These approaches are not mutually exclusive. A single deployment can use all three:
- Some PEPs may send fully-qualified descriptors for domain-specific resource synthesis
- Other resources may resolve via PolicyDomain selectors
- Premium users can add external resolution for resources not matched by selectors

When an MRN string is provided, resolution follows this order:
1. **PolicyDomain selectors** — Local patterns defined in the `resources` section
2. **External resolver** — Custom integration (Premium only, if configured)
3. **Default resource group** — Fallback when no match is found
:::

## MRN Format

All approaches use Manetu Resource Notation (MRN) to identify resources:

```
mrn:<type>:<namespace>:<resource-class>:<instance>
```

Examples:
- `mrn:vault:acme.com:secret:api-key`
- `mrn:iam:role:admin`
- `mrn:app:myservice:user:12345`
- `mrn:data:analytics:report:monthly`

---

## Approach 1: MRN String with Selector Resolution

The simplest approach: provide only the resource's MRN string and let the PolicyEngine resolve metadata using pattern matching.

```json
{
  "resource": "mrn:app:myservice:document:12345"
}
```

### How It Works

The PolicyEngine matches the MRN against regex patterns (selectors) defined in your PolicyDomain configuration:

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  resources:
    - name: user-documents
      selector:
        - "mrn:app:.*:document:.*"
      group: "mrn:iam:resource-group:documents"
      annotations:
        - name: classification
          value: "\"MODERATE\""

    - name: admin-resources
      selector:
        - "mrn:admin:.*"
      group: "mrn:iam:resource-group:admin"
      annotations:
        - name: classification
          value: "\"HIGH\""
```

When a PEP sends `mrn:app:myservice:document:12345`, the PolicyEngine:

1. Matches against configured selectors
2. Finds `mrn:app:.*:document:.*` matches
3. Assigns the resource to `mrn:iam:resource-group:documents`
4. Applies the `classification: "MODERATE"` annotation
5. Evaluates policies using the resolved metadata

If no selector matches, the resource is assigned to the default resource group.

### Benefits

- **Minimal PEP complexity** — PEPs only need the resource identifier
- **Centralized control** — Policy authors manage all resource metadata in configuration
- **No code changes for policy updates** — Modify resource routing without redeploying applications

### Limitations

- **Pattern-based granularity** — Resources are grouped by MRN patterns, not individual properties
- **Static metadata** — Classification and annotations are determined by which pattern matches
- **No ownership tracking** — Cannot assign per-resource owners through selectors

### Best For

- Resources that naturally group by naming patterns
- Organizations where policy authors should control resource classification
- Scenarios where resource metadata is relatively stable

---

## Approach 2: MRN String with External Resolution <FeatureChip variant="premium" /> {#approach-2-mrn-string-with-external-resolution}

Extends selector resolution by dynamically resolving metadata from external systems. This approach maintains the same simple PEP interface—just send an MRN string—while enabling per-resource granularity.

```json
{
  "resource": "mrn:app:myservice:document:12345"
}
```

### How It Works

The Premium Edition allows you to integrate custom resolvers that fetch metadata at decision time. When an MRN doesn't match any PolicyDomain selector, the external resolver is consulted before falling back to the default resource group.

Custom resolvers can:
- Query your asset management database
- Call internal APIs
- Look up classification from a data catalog
- Retrieve ownership from your identity provider

The PEP still sends just an MRN string, but the PolicyEngine can resolve rich, per-resource metadata dynamically.

:::tip Combining with Selectors
External resolution works alongside PolicyDomain selectors, not instead of them. You can define selectors for resources that fit patterns and rely on external resolution for everything else. This hybrid approach lets you handle common cases efficiently while maintaining flexibility for exceptions.
:::

### Benefits

- **Simple PEP interface** — Same as Approach 1; PEPs only send the MRN
- **Per-resource granularity** — Each resource can have unique metadata regardless of naming patterns
- **Dynamic metadata** — Classification, ownership, and annotations can change without policy updates
- **Ownership support** — Resolvers can return owner information for each resource
- **External system integration** — Leverage existing asset registries, CMDBs, and data catalogs

### Considerations

- **Resolver development** — You need to implement and maintain the resolver integration
- **Latency impact** — External lookups add time to policy evaluation (mitigated by caching)
- **Dependency management** — Policy decisions depend on resolver availability

### Best For

- Organizations with existing asset management systems
- Resources where classification or ownership is managed externally
- Scenarios requiring per-resource metadata without PEP changes
- Keeping PEP implementations simple while gaining full flexibility

---

## Approach 3: Fully-Qualified Descriptor

The PEP provides complete resource metadata directly, bypassing all resolution.

```json
{
  "resource": {
    "id": "mrn:app:myservice:document:12345",
    "owner": "user@example.com",
    "group": "mrn:iam:resource-group:documents",
    "classification": "MODERATE",
    "annotations": {
      "department": "engineering",
      "sensitive": true
    }
  }
}
```

### Resource Object Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique resource identifier (MRN) — has first-class representation in AccessRecord |
| `owner` | No | MRN or identifier of the resource owner |
| `group` | Yes | MRN of the resource group — used to select the Phase 3 resource policy |
| `classification` | No | Security classification level |
| `annotations` | No | Custom key-value metadata |

:::note
When using the MRN string format, the PolicyEngine automatically populates `resource.id` and `resource.group` from resolution before processing. With Fully-Qualified Descriptors, the PEP must provide these fields directly:
- **`id`** — Required for complete audit records (first-class field in AccessRecord)
- **`group`** — Required for policy evaluation (Phase 3 is mandatory; omitting this field will result in a DENY)
:::

### Classification Levels

| Level | Value | Description |
|-------|-------|-------------|
| `LOW` | 1 | Public data |
| `MODERATE` | 2 | Internal data |
| `HIGH` | 3 | Confidential data |
| `MAXIMUM` | 4 | Top secret data |
| `UNASSIGNED` | 5 | Not yet classified |

### How It Works

The PolicyEngine uses the provided metadata exactly as-is. No selectors are consulted, no external resolvers are called.

### Benefits

- **Complete control** — PEP determines all resource metadata
- **Per-resource granularity** — Every resource can have unique properties
- **No resolution latency** — Metadata is already present in the request
- **Ownership support** — PEP can specify resource owners directly

### Considerations

- **PEP complexity** — Application must know and provide all resource metadata
- **Distributed maintenance** — Changes to resource classification require PEP updates
- **Consistency challenges** — Multiple PEPs must agree on metadata for shared resources

### Example: Dynamic Resource Metadata

```go
// Application knows the document details from its database
doc := getDocumentFromDB(documentID)

porc := map[string]interface{}{
    "principal": principal,
    "operation": "api:documents:read",
    "resource": map[string]interface{}{
        "id":             fmt.Sprintf("mrn:app:docs:document:%s", doc.ID),
        "owner":          doc.OwnerEmail,
        "group":          doc.ResourceGroup,
        "classification": doc.Classification,
        "annotations": map[string]interface{}{
            "department": doc.Department,
            "created":    doc.CreatedAt.Format(time.RFC3339),
        },
    },
    "context": context,
}
```

### Best For

- Applications that are the authoritative source for resource metadata
- Resources with frequently-changing properties
- Single-PEP architectures where the application owns resource data
- **Domain-specific resource synthesis** — When the PEP must construct resources dynamically, such as sub-resource egress filtering where the resource represents a subset or derivative of stored data
- Scenarios where owner-based policies require per-request ownership determination

---

## Choosing an Approach

### Decision Matrix

| Consideration | Selector Resolution | External Resolution | Fully-Qualified |
|--------------|---------------------|---------------------|-----------------|
| **Availability** | All editions | <FeatureChip variant="premium" /> | All editions |
| **PEP complexity** | Minimal | Minimal | Higher |
| **Metadata granularity** | Pattern-based | Per-resource | Per-resource |
| **Metadata source** | PolicyDomain config | Your external systems | Application |
| **Owner tracking** | Not available | Available | Available |
| **Update workflow** | Edit PolicyDomain | Update external system | Update PEP code |
| **Resolution latency** | Fast (in-memory) | Variable (external call) | None |

### Quick Decision Guide

**Choose Selector Resolution when:**
- Resources group naturally by naming conventions
- Metadata is stable and pattern-based
- You want maximum PEP simplicity
- Policy authors should control classification

**Add External Resolution (Premium) when:**
- You need per-resource metadata without complicating PEPs
- An external system is the source of truth for resource properties
- You want simple PEPs but full flexibility
- Resource ownership or classification is managed outside policy config
- You want to handle resources that don't fit selector patterns

**Choose Fully-Qualified Descriptors when:**
- The application owns and manages resource metadata
- The PEP must synthesize resources dynamically (e.g., sub-resource filtering)
- Resources have highly dynamic properties
- You want to avoid any resolution overhead

---

## Configuring Selector Resolution

For the Community Edition, configure resource resolution in the PolicyDomain's `resources` section (v1alpha4+):

```yaml
apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  resources:
    - name: internal-docs
      description: "Internal documentation"
      selector:
        - "mrn:docs:internal:.*"
        - "mrn:wiki:company:.*"
      group: "mrn:iam:resource-group:internal"
      annotations:
        - name: classification
          value: "\"MODERATE\""
        - name: audit_required
          value: "false"

    - name: secrets
      description: "Secret and credential resources"
      selector:
        - "mrn:secret:.*"
        - "mrn:vault:.*:credential:.*"
      group: "mrn:iam:resource-group:restricted"
      annotations:
        - name: classification
          value: "\"MAXIMUM\""
        - name: audit_required
          value: "true"
```

See [Resources Schema Reference](/reference/schema/resources) for complete documentation.
