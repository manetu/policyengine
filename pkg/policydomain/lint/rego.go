//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"fmt"
	"strings"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/open-policy-agent/opa/v1/ast"
)

// lintRegoAST validates Rego syntax for all entities in the given pre-parsed
// domain models using the OPA AST parser. Unlike the validation package's
// RegoValidator, this preserves line/column information from ast.Errors.
//
// domainKeyMap maps domain name to its logical key (file path or name), used
// to populate Location.File on returned diagnostics.
func lintRegoAST(models []*policydomain.IntermediateModel, domainKeyMap map[string]string, regoOffsets map[string]map[string]int) []Diagnostic {
	var diagnostics []Diagnostic

	for _, domain := range models {
		key := domainKeyMap[domain.Name]
		fileOffsets := regoOffsets[key]

		for libID, library := range domain.PolicyLibraries {
			if strings.TrimSpace(library.Rego) == "" {
				continue
			}
			offset := fileOffsets["library:"+libID]
			d := parseRegoCode(library.Rego, Entity{
				Domain: domain.Name,
				Type:   "library",
				ID:     libID,
				Field:  "rego",
			}, key, offset)
			diagnostics = append(diagnostics, d...)
		}

		for policyID, policy := range domain.Policies {
			if strings.TrimSpace(policy.Rego) == "" {
				continue
			}
			offset := fileOffsets["policy:"+policyID]
			d := parseRegoCode(policy.Rego, Entity{
				Domain: domain.Name,
				Type:   "policy",
				ID:     policyID,
				Field:  "rego",
			}, key, offset)
			diagnostics = append(diagnostics, d...)
		}

		for i, mapper := range domain.Mappers {
			if strings.TrimSpace(mapper.Rego) == "" {
				continue
			}
			mapperID := mapper.IDSpec.ID
			if mapperID == "" {
				mapperID = fmt.Sprintf("mapper[%d]", i)
			}
			offset := fileOffsets["mapper:"+mapperID]
			d := parseRegoCode(mapper.Rego, Entity{
				Domain: domain.Name,
				Type:   "mapper",
				ID:     mapperID,
				Field:  "rego",
			}, key, offset)
			diagnostics = append(diagnostics, d...)
		}
	}

	return diagnostics
}

// parseRegoCode parses a Rego snippet and converts any ast.Errors to Diagnostics.
// regoLineOffset is the 1-based YAML line where the Rego content starts (0 = unknown).
func parseRegoCode(regoCode string, entity Entity, filePath string, regoLineOffset int) []Diagnostic {
	moduleID := fmt.Sprintf("%s:%s", entity.Type, entity.ID)
	_, err := ast.ParseModuleWithOpts(moduleID, regoCode, ast.ParserOptions{RegoVersion: ast.RegoV0})
	if err == nil {
		return nil
	}

	astErrs, ok := err.(ast.Errors)
	if !ok {
		// Fallback: unknown error type
		return []Diagnostic{{
			Source:   SourceRego,
			Severity: SeverityError,
			Location: Location{File: filePath},
			Entity:   entity,
			Message:  err.Error(),
		}}
	}

	diagnostics := make([]Diagnostic, 0, len(astErrs))
	for _, astErr := range astErrs {
		d := Diagnostic{
			Source:   SourceRego,
			Severity: SeverityError,
			Location: Location{File: filePath},
			Entity:   entity,
			Message:  astErr.Message,
			Category: astErr.Code,
		}
		if astErr.Location != nil {
			regoLine := astErr.Location.Row
			regoCol := astErr.Location.Col
			if regoLineOffset > 0 && regoLine > 0 {
				d.Location.Start.Line = regoLineOffset + regoLine - 1
			} else {
				d.Location.Start.Line = regoLine
			}
			d.Location.Start.Column = regoCol
		}
		d.RegoOffset = regoLineOffset
		diagnostics = append(diagnostics, d)
	}
	return diagnostics
}
