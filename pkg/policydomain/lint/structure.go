//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// lintStructure validates structural constraints on a raw PolicyDomain YAML
// document that are not caught by YAML syntax parsing alone.
//
// It walks the YAML node tree to detect:
//   - Missing or empty metadata.name
//   - Missing or empty mrn/name on individual entities
//   - Duplicate MRNs within a section
//   - Missing rego field on policies, policy-libraries, and mappers
//   - Missing selector field on operations, mappers, and resources
//
// This phase runs after selector validation (Phase 1.5) and before the full
// model parse (Phase 2), so diagnostics include line/column positions from
// the YAML node tree even when subsequent parsing would also fail.
func lintStructure(data []byte, key string) []Diagnostic {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		// YAML syntax errors are reported by lintYAML; nothing to do here.
		return nil
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil
	}

	var diagnostics []Diagnostic

	// Extract domain name from metadata.name (also validates it exists).
	domainName := ""
	metaNode := findMappingValue(doc, "metadata")
	if metaNode == nil {
		diagnostics = append(diagnostics, Diagnostic{
			Source:   SourceSchema,
			Severity: SeverityError,
			Location: Location{File: key, Start: Position{Line: doc.Line, Column: doc.Column}},
			Message:  "missing metadata section",
		})
	} else {
		nameNode := findMappingValue(metaNode, "name")
		if nameNode == nil || (nameNode.Kind == yaml.ScalarNode && nameNode.Value == "") {
			line, col := doc.Line, doc.Column
			if metaNode != nil {
				line, col = metaNode.Line, metaNode.Column
			}
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceSchema,
				Severity: SeverityError,
				Location: Location{File: key, Start: Position{Line: line, Column: col}},
				Entity:   Entity{Field: "metadata.name"},
				Message:  "metadata.name is required and must not be empty",
			})
		} else if nameNode.Kind == yaml.ScalarNode {
			domainName = nameNode.Value
		}
	}

	spec := findMappingValue(doc, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return diagnostics
	}

	// Sections that have a per-entity MRN/name identifier.
	// hasRego: entity must have a non-empty rego field.
	// hasSelector: entity must have a non-empty selector list.
	for _, section := range []struct {
		key         string
		entityType  string
		hasRego     bool
		hasSelector bool
	}{
		{"policies", "policy", true, false},
		{"policy-libraries", "library", true, false},
		{"policyLibraries", "library", true, false},
		{"roles", "role", false, false},
		{"groups", "group", false, false},
		{"resource-groups", "resource-group", false, false},
		{"resourceGroups", "resource-group", false, false},
		{"scopes", "scope", false, false},
		{"operations", "operation", false, true},
		{"mappers", "mapper", true, true},
		{"resources", "resource", false, true},
	} {
		sectionNode := findMappingValue(spec, section.key)
		if sectionNode == nil {
			continue
		}
		switch sectionNode.Kind {
		case yaml.SequenceNode:
			diagnostics = append(diagnostics, lintStructureList(
				sectionNode, section.entityType, domainName, key,
				section.hasRego, section.hasSelector,
			)...)
		case yaml.MappingNode:
			diagnostics = append(diagnostics, lintStructureMap(
				sectionNode, section.entityType, domainName, key,
				section.hasRego, section.hasSelector,
			)...)
		}
	}

	return diagnostics
}

// lintStructureList validates v1alpha3/v1alpha4-style list sections where each
// entity is a mapping with an "mrn" or "name" scalar.
func lintStructureList(seq *yaml.Node, entityType, domainName, key string, hasRego, hasSelector bool) []Diagnostic {
	var diagnostics []Diagnostic
	seen := make(map[string]int) // id → first-seen line

	for i, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}

		// Resolve entity ID from mrn or name field.
		id := findScalarValue(item, "mrn")
		if id == "" {
			id = findScalarValue(item, "name")
		}

		idNode := findMappingValue(item, "mrn")
		if idNode == nil {
			idNode = findMappingValue(item, "name")
		}

		if id == "" {
			// Entity has no mrn/name — report and use index as fallback.
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceSchema,
				Severity: SeverityError,
				Location: Location{File: key, Start: Position{Line: item.Line, Column: item.Column}},
				Entity:   Entity{Domain: domainName, Type: entityType, ID: fmt.Sprintf("%s[%d]", entityType, i), Field: "mrn"},
				Message:  fmt.Sprintf("%s entry at index %d is missing required mrn field", entityType, i),
			})
		} else if firstLine, dup := seen[id]; dup {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceDuplicate,
				Severity: SeverityError,
				Location: Location{File: key, Start: Position{Line: idNode.Line, Column: idNode.Column}},
				Entity:   Entity{Domain: domainName, Type: entityType, ID: id, Field: "mrn"},
				Message:  fmt.Sprintf("duplicate %s mrn %q (first defined at line %d)", entityType, id, firstLine),
			})
		} else {
			seen[id] = item.Line
		}

		entityID := id
		if entityID == "" {
			entityID = fmt.Sprintf("%s[%d]", entityType, i)
		}

		if hasRego {
			diagnostics = append(diagnostics, checkRegoField(item, entityType, entityID, domainName, key)...)
		}
		if hasSelector {
			diagnostics = append(diagnostics, checkSelectorField(item, entityType, entityID, domainName, key)...)
		}
	}

	return diagnostics
}

// lintStructureMap validates v1beta1-style map sections where entity keys are
// the IDs and values are the entity bodies.
func lintStructureMap(m *yaml.Node, entityType, domainName, key string, hasRego, hasSelector bool) []Diagnostic {
	var diagnostics []Diagnostic
	seen := make(map[string]int) // id → first-seen line

	for i := 0; i+1 < len(m.Content); i += 2 {
		keyNode := m.Content[i]
		valueNode := m.Content[i+1]
		id := keyNode.Value

		if id == "" {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceSchema,
				Severity: SeverityError,
				Location: Location{File: key, Start: Position{Line: keyNode.Line, Column: keyNode.Column}},
				Entity:   Entity{Domain: domainName, Type: entityType, Field: "name"},
				Message:  fmt.Sprintf("%s entry has an empty key", entityType),
			})
			continue
		}

		if firstLine, dup := seen[id]; dup {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceDuplicate,
				Severity: SeverityError,
				Location: Location{File: key, Start: Position{Line: keyNode.Line, Column: keyNode.Column}},
				Entity:   Entity{Domain: domainName, Type: entityType, ID: id, Field: "name"},
				Message:  fmt.Sprintf("duplicate %s name %q (first defined at line %d)", entityType, id, firstLine),
			})
		} else {
			seen[id] = keyNode.Line
		}

		if valueNode.Kind != yaml.MappingNode {
			continue
		}

		if hasRego {
			diagnostics = append(diagnostics, checkRegoField(valueNode, entityType, id, domainName, key)...)
		}
		if hasSelector {
			diagnostics = append(diagnostics, checkSelectorField(valueNode, entityType, id, domainName, key)...)
		}
	}

	return diagnostics
}

// checkRegoField emits a SourceSchema diagnostic if the rego field is absent or empty.
func checkRegoField(item *yaml.Node, entityType, entityID, domainName, key string) []Diagnostic {
	regoNode := findMappingValue(item, "rego")
	if regoNode == nil || (regoNode.Kind == yaml.ScalarNode && regoNode.Value == "") {
		line, col := item.Line, item.Column
		if regoNode != nil {
			line, col = regoNode.Line, regoNode.Column
		}
		return []Diagnostic{{
			Source:   SourceSchema,
			Severity: SeverityError,
			Location: Location{File: key, Start: Position{Line: line, Column: col}},
			Entity:   Entity{Domain: domainName, Type: entityType, ID: entityID, Field: "rego"},
			Message:  fmt.Sprintf("%s %q is missing required rego field", entityType, entityID),
		}}
	}
	return nil
}

// checkSelectorField emits a SourceSchema diagnostic if the selector field is absent or empty.
func checkSelectorField(item *yaml.Node, entityType, entityID, domainName, key string) []Diagnostic {
	selNode := findMappingValue(item, "selector")
	if selNode == nil || (selNode.Kind == yaml.SequenceNode && len(selNode.Content) == 0) {
		line, col := item.Line, item.Column
		if selNode != nil {
			line, col = selNode.Line, selNode.Column
		}
		return []Diagnostic{{
			Source:   SourceSchema,
			Severity: SeverityError,
			Location: Location{File: key, Start: Position{Line: line, Column: col}},
			Entity:   Entity{Domain: domainName, Type: entityType, ID: entityID, Field: "selector"},
			Message:  fmt.Sprintf("%s %q is missing required selector field", entityType, entityID),
		}}
	}
	return nil
}
