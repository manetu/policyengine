//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"gopkg.in/yaml.v3"
)

// computeRegoOffsets walks the raw bytes of a PolicyDomain YAML document and
// returns the starting YAML line number for each embedded Rego block.
//
// Keys are "entityType:entityID" (e.g. "policy:mrn:iam:policy:authz").
// Values are 1-based line numbers for the first line of Rego content
// (i.e. the line after the block-scalar indicator `|`).
func computeRegoOffsets(data []byte) (map[string]int, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	offsets := make(map[string]int)
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		extractOffsets(root.Content[0], offsets)
	}
	return offsets, nil
}

// extractOffsets navigates the YAML node tree to find `rego:` values under
// spec.policy-libraries, spec.policies, spec.policyLibraries, spec.mappers, etc.
func extractOffsets(root *yaml.Node, offsets map[string]int) {
	if root == nil || root.Kind != yaml.MappingNode {
		return
	}

	spec := findMappingValue(root, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return
	}

	// Process each known entity-bearing section
	for _, section := range []struct {
		key        string
		entityType string
	}{
		{"policy-libraries", "library"},
		{"policyLibraries", "library"},
		{"policies", "policy"},
		{"mappers", "mapper"},
	} {
		sectionNode := findMappingValue(spec, section.key)
		if sectionNode == nil {
			continue
		}
		switch sectionNode.Kind {
		case yaml.SequenceNode:
			extractOffsetsFromList(sectionNode, section.entityType, offsets)
		case yaml.MappingNode:
			extractOffsetsFromMap(sectionNode, section.entityType, offsets)
		}
	}
}

// extractOffsetsFromList handles v1alpha3-style list entities:
//
//   - mrn: "mrn:iam:policy:foo"
//     rego: |
//     package authz
func extractOffsetsFromList(seq *yaml.Node, entityType string, offsets map[string]int) {
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		id := findScalarValue(item, "mrn")
		if id == "" {
			id = findScalarValue(item, "id")
		}
		if id == "" {
			continue
		}
		regoNode := findMappingValue(item, "rego")
		if regoNode != nil {
			offsets[entityType+":"+id] = regoContentLine(regoNode)
		}
	}
}

// extractOffsetsFromMap handles v1beta1-style map entities:
//
//	my-policy:
//	  rego: |
//	    package authz
func extractOffsetsFromMap(m *yaml.Node, entityType string, offsets map[string]int) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		id := m.Content[i].Value
		value := m.Content[i+1]
		if value.Kind != yaml.MappingNode {
			continue
		}
		regoNode := findMappingValue(value, "rego")
		if regoNode != nil {
			offsets[entityType+":"+id] = regoContentLine(regoNode)
		}
	}
}

// regoContentLine returns the 1-based YAML line where Rego content starts.
// For block scalars (| or >), content starts on the line after the indicator.
func regoContentLine(node *yaml.Node) int {
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle {
		return node.Line + 1
	}
	return node.Line
}

// findMappingValue returns the value node for a given key in a MappingNode.
func findMappingValue(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// findScalarValue returns the string value of a scalar key in a MappingNode.
func findScalarValue(m *yaml.Node, key string) string {
	v := findMappingValue(m, key)
	if v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}
