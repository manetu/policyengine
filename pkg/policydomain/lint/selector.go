//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// lintSelectors validates selector regex patterns on operations, mappers, and
// resources within a raw PolicyDomain YAML document.
//
// It walks the YAML node tree to find selector sequences and attempts to compile
// each pattern, emitting a structured Diagnostic for any invalid regex. This
// phase runs on the raw bytes before LoadFromBytes so that entity-aware
// diagnostics (with entity type, ID, and YAML line number) are produced even
// when the full parse would fail due to the bad pattern.
func lintSelectors(data []byte, key string) []Diagnostic {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		// YAML syntax errors are reported by lintYAML; nothing to do here.
		return nil
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}

	doc := root.Content[0]

	domainName := ""
	if meta := findMappingValue(doc, "metadata"); meta != nil {
		domainName = findScalarValue(meta, "name")
	}

	spec := findMappingValue(doc, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return nil
	}

	var diagnostics []Diagnostic

	for _, section := range []struct {
		key        string
		entityType string
	}{
		{"operations", "operation"},
		{"mappers", "mapper"},
		{"resources", "resource"},
	} {
		sectionNode := findMappingValue(spec, section.key)
		if sectionNode == nil || sectionNode.Kind != yaml.SequenceNode {
			continue
		}
		for i, item := range sectionNode.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			entityID := findScalarValue(item, "name")
			if entityID == "" {
				entityID = findScalarValue(item, "mrn")
			}
			if entityID == "" {
				entityID = fmt.Sprintf("%s[%d]", section.entityType, i)
			}

			selectorNode := findMappingValue(item, "selector")
			if selectorNode == nil || selectorNode.Kind != yaml.SequenceNode {
				continue
			}

			for _, sel := range selectorNode.Content {
				if sel.Kind != yaml.ScalarNode {
					continue
				}
				pattern := selectorAnchorPattern(sel.Value)
				if _, err := regexp.Compile(pattern); err != nil {
					diagnostics = append(diagnostics, Diagnostic{
						Source:   SourceSelector,
						Severity: SeverityError,
						Location: Location{
							File:  key,
							Start: Position{Line: sel.Line, Column: sel.Column},
						},
						Entity: Entity{
							Domain: domainName,
							Type:   section.entityType,
							ID:     entityID,
							Field:  "selector",
						},
						Message: fmt.Sprintf("invalid selector regex %q: %s", sel.Value, err.Error()),
					})
				}
			}
		}
	}

	return diagnostics
}

// selectorAnchorPattern ensures the pattern is anchored with ^ and $,
// matching the behaviour of the v1alpha3/v1alpha4/v1beta1 parsers.
func selectorAnchorPattern(pattern string) string {
	result := pattern
	if !strings.HasPrefix(result, "^") {
		result = "^" + result
	}
	if !strings.HasSuffix(result, "$") {
		result = result + "$"
	}
	return result
}
