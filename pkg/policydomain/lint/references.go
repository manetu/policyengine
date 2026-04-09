//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// enrichReferenceLocations post-processes reference and cycle diagnostics to
// populate line/column positions by walking the raw YAML node tree for each
// affected file.
//
// This enrichment runs after convertValidationErrors, which produces diagnostics
// with Source==SourceReference but zero line/column. The Entity.Type, Entity.ID,
// and Entity.Field fields carry enough information to locate the offending node.
func enrichReferenceLocations(diagnostics []Diagnostic, rawData map[string][]byte, domainKeyMap map[string]string) []Diagnostic {
	for i := range diagnostics {
		d := &diagnostics[i]
		if d.Source != SourceReference {
			continue
		}
		if d.Location.Start.Line != 0 {
			// Already has position information.
			continue
		}

		fileKey := domainKeyMap[d.Entity.Domain]
		if fileKey == "" {
			continue
		}
		data, ok := rawData[fileKey]
		if !ok {
			continue
		}

		pos := findReferencePosition(data, d.Entity.Type, d.Entity.ID, d.Entity.Field)
		if pos.Line != 0 {
			d.Location.Start = pos
		}
	}
	return diagnostics
}

// findReferencePosition parses the YAML document and navigates to the field
// node that contains the invalid reference, returning its position.
// Returns a zero Position if the node cannot be found.
func findReferencePosition(data []byte, entityType, entityID, field string) Position {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Position{}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return Position{}
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return Position{}
	}

	spec := findMappingValue(doc, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return Position{}
	}

	sectionKey, idField := entitySectionKey(entityType)
	if sectionKey == "" {
		return Position{}
	}

	sectionNode := findMappingValue(spec, sectionKey)
	if sectionNode == nil {
		// Try alternate section key (e.g., "policyLibraries" vs "policy-libraries").
		if alt := entitySectionKeyAlt(entityType); alt != "" {
			sectionNode = findMappingValue(spec, alt)
		}
	}
	if sectionNode == nil {
		return Position{}
	}

	switch sectionNode.Kind {
	case yaml.SequenceNode:
		return findFieldInList(sectionNode, entityID, idField, field)
	case yaml.MappingNode:
		return findFieldInMap(sectionNode, entityID, field)
	}
	return Position{}
}

// findFieldInList finds entityID in a sequence section and returns the position
// of the specified field node within that entity.
func findFieldInList(seq *yaml.Node, entityID, idField, field string) Position {
	// Check if this is an index-based ID like "operation[2]" or "resource[0]".
	if idx, ok := parseIndexID(entityID); ok {
		if idx < len(seq.Content) {
			item := seq.Content[idx]
			if item.Kind == yaml.MappingNode {
				return fieldPosition(item, field)
			}
		}
		return Position{}
	}

	// MRN-based lookup: find the item whose mrn or name matches entityID.
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		id := findScalarValue(item, idField)
		if id == "" {
			id = findScalarValue(item, "name")
		}
		if id == entityID {
			return fieldPosition(item, field)
		}
	}
	return Position{}
}

// findFieldInMap finds entityID as a key in a map section and returns the
// position of the specified field node within that entity's value.
func findFieldInMap(m *yaml.Node, entityID, field string) Position {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == entityID {
			value := m.Content[i+1]
			if value.Kind == yaml.MappingNode {
				return fieldPosition(value, field)
			}
		}
	}
	return Position{}
}

// fieldPosition returns the position of a named field node within a mapping,
// falling back to the mapping's own position if the field is not found.
func fieldPosition(m *yaml.Node, field string) Position {
	// For composite fields like "roles[0]", find the "roles" field.
	baseField := field
	if idx := strings.Index(field, "["); idx >= 0 {
		baseField = field[:idx]
	}

	node := findMappingValue(m, baseField)
	if node != nil {
		return Position{Line: node.Line, Column: node.Column}
	}
	// Fall back to the entity mapping itself.
	return Position{Line: m.Line, Column: m.Column}
}

// parseIndexID parses an index-based entity ID like "operation[2]" or "resource[0]".
// Returns the index and true if successful.
func parseIndexID(id string) (int, bool) {
	lbrace := strings.Index(id, "[")
	rbrace := strings.Index(id, "]")
	if lbrace < 0 || rbrace <= lbrace {
		return 0, false
	}
	n, err := strconv.Atoi(id[lbrace+1 : rbrace])
	if err != nil {
		return 0, false
	}
	return n, true
}

// entitySectionKey returns the primary YAML spec section key and the ID field
// name for a given entity type.
func entitySectionKey(entityType string) (sectionKey, idField string) {
	switch entityType {
	case "policy":
		return "policies", "mrn"
	case "library":
		return "policy-libraries", "mrn"
	case "role":
		return "roles", "mrn"
	case "group":
		return "groups", "mrn"
	case "resource-group":
		return "resource-groups", "mrn"
	case "scope":
		return "scopes", "mrn"
	case "operation":
		return "operations", "mrn"
	case "resource":
		return "resources", "mrn"
	default:
		return "", ""
	}
}

// entitySectionKeyAlt returns an alternate section key for entity types that
// use camelCase in some apiVersions (e.g., v1beta1 "policyLibraries").
func entitySectionKeyAlt(entityType string) string {
	switch entityType {
	case "library":
		return "policyLibraries"
	case "resource-group":
		return "resourceGroups"
	default:
		return ""
	}
}
