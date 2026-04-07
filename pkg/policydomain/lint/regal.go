//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"fmt"
	"strings"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/open-policy-agent/regal/pkg/linter"
	"github.com/open-policy-agent/regal/pkg/report"
	"github.com/open-policy-agent/regal/pkg/rules"
)

// runRegal extracts all Rego from the given pre-parsed domain models and runs
// Regal lint rules. Returns structured diagnostics with line/column from
// Regal's violation locations.
//
// domainKeyMap maps domain name to its logical key (file path or name), used
// to populate Location.File on returned diagnostics.
func runRegal(ctx context.Context, models []*policydomain.IntermediateModel, domainKeyMap map[string]string, regoOffsets map[string]map[string]int) ([]Diagnostic, error) {
	// Map synthetic filename → Rego content
	regoFiles := make(map[string]string)
	// Map synthetic filename → entityInfo ("key:entityType:entityID")
	fileEntityMap := make(map[string]string)

	for _, domain := range models {
		key := domainKeyMap[domain.Name]

		for libID, library := range domain.PolicyLibraries {
			if strings.TrimSpace(library.Rego) == "" {
				continue
			}
			synth := syntheticRegoName(key, "library", libID)
			regoFiles[synth] = library.Rego
			fileEntityMap[synth] = fmt.Sprintf("%s:library:%s", key, libID)
		}

		for policyID, policy := range domain.Policies {
			if strings.TrimSpace(policy.Rego) == "" {
				continue
			}
			synth := syntheticRegoName(key, "policy", policyID)
			regoFiles[synth] = policy.Rego
			fileEntityMap[synth] = fmt.Sprintf("%s:policy:%s", key, policyID)
		}

		for i, mapper := range domain.Mappers {
			if strings.TrimSpace(mapper.Rego) == "" {
				continue
			}
			mapperID := mapper.IDSpec.ID
			if mapperID == "" {
				mapperID = fmt.Sprintf("mapper[%d]", i)
			}
			synth := syntheticRegoName(key, "mapper", mapperID)
			regoFiles[synth] = mapper.Rego
			fileEntityMap[synth] = fmt.Sprintf("%s:mapper:%s", key, mapperID)
		}
	}

	if len(regoFiles) == 0 {
		return nil, nil
	}

	input, err := rules.InputFromMap(regoFiles, nil)
	if err != nil {
		return nil, fmt.Errorf("regal: failed to parse Rego: %w", err)
	}

	regalLinter := linter.NewLinter().WithInputModules(&input)
	regalReport, err := regalLinter.Lint(ctx)
	if err != nil {
		return nil, fmt.Errorf("regal: linting failed: %w", err)
	}

	return convertRegalViolations(regalReport.Violations, fileEntityMap, regoOffsets), nil
}

// convertRegalViolations converts Regal report.Violation values to Diagnostics.
func convertRegalViolations(violations []report.Violation, fileEntityMap map[string]string, regoOffsets map[string]map[string]int) []Diagnostic {
	diagnostics := make([]Diagnostic, 0, len(violations))

	for _, v := range violations {
		entityInfo := fileEntityMap[v.Location.File]

		d := Diagnostic{
			Source:   SourceRegal,
			Severity: regalSeverity(v.Level),
			Message:  v.Title,
			Category: v.Category,
		}

		if v.Description != "" {
			d.Message = v.Title + ": " + v.Description
		}

		if entityInfo != "" {
			parts := strings.SplitN(entityInfo, ":", 3)
			if len(parts) == 3 {
				sourceFile, entityType, entityID := parts[0], parts[1], parts[2]
				d.Location.File = sourceFile
				d.Entity = Entity{Type: entityType, ID: entityID, Field: "rego"}

				// Map Regal line (within Rego snippet) to YAML file line
				if v.Location.Row > 0 {
					fileOffsets := regoOffsets[sourceFile]
					offset := fileOffsets[entityType+":"+entityID]
					if offset > 0 {
						d.Location.Start.Line = offset + v.Location.Row - 1
					} else {
						d.Location.Start.Line = v.Location.Row
					}
					d.Location.Start.Column = v.Location.Column
					d.RegoOffset = offset
				}
			}
		} else {
			d.Location.File = v.Location.File
			d.Location.Start = Position{Line: v.Location.Row, Column: v.Location.Column}
		}

		diagnostics = append(diagnostics, d)
	}

	return diagnostics
}

// regalSeverity converts a Regal level string to Severity.
func regalSeverity(level string) Severity {
	switch strings.ToLower(level) {
	case "error":
		return SeverityError
	case "warning":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// syntheticRegoName creates a deterministic synthetic filename for a Rego entity.
// This must match the format used in the existing CLI regal.go so that existing
// tests and output remain consistent.
func syntheticRegoName(sourceFile, entityType, entityID string) string {
	safeID := strings.ReplaceAll(entityID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	return fmt.Sprintf("%s_%s_%s.rego", sourceFile, entityType, safeID)
}
