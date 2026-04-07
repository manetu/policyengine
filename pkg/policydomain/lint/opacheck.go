//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"fmt"
	"strings"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/open-policy-agent/opa/v1/ast"
)

// regoVersion selects the OPA Rego language version for compilation.
type regoVersion int

const (
	regoV0 regoVersion = iota
	regoV1
)

func (rv regoVersion) opaVersion() ast.RegoVersion {
	if rv == regoV1 {
		return ast.RegoV1
	}
	return ast.RegoV0
}

// runOPACheck performs full in-process OPA compilation on all entities,
// catching type errors, undefined references, and other semantic issues that
// the AST parser alone does not detect.
//
// domainKeyMap maps domain name to its logical key (file path or name), used
// to populate Location.File on returned diagnostics.
func runOPACheck(reg *registry.Registry, models []*policydomain.IntermediateModel, domainKeyMap map[string]string, regoOffsets map[string]map[string]int, rv regoVersion) []Diagnostic {
	var diagnostics []Diagnostic

	parserOpts := ast.ParserOptions{RegoVersion: rv.opaVersion()}

	// Parse all libraries first (needed as dependencies for policies)
	allLibraries := collectAllLibraries(models, domainKeyMap, parserOpts)

	// Check all libraries together
	diagnostics = append(diagnostics, checkModuleGroup(allLibraries, regoOffsets)...)

	// Check each policy with its resolved library dependencies
	diagnostics = append(diagnostics, checkPoliciesWithDeps(models, domainKeyMap, reg, parserOpts, regoOffsets)...)

	// Check each mapper individually
	diagnostics = append(diagnostics, checkMappers(models, domainKeyMap, parserOpts, regoOffsets)...)

	return diagnostics
}

type parsedModule struct {
	file   string // source YAML file path
	entity Entity
	module *ast.Module
}

// collectAllLibraries parses all library Rego from all domain models.
func collectAllLibraries(models []*policydomain.IntermediateModel, domainKeyMap map[string]string, opts ast.ParserOptions) []parsedModule {
	var result []parsedModule
	for _, domain := range models {
		key := domainKeyMap[domain.Name]
		for libID, library := range domain.PolicyLibraries {
			if strings.TrimSpace(library.Rego) == "" {
				continue
			}
			moduleID := fmt.Sprintf("library:%s", libID)
			m, err := ast.ParseModuleWithOpts(moduleID, library.Rego, opts)
			if err != nil {
				continue // parse errors captured in lintRegoAST phase
			}
			result = append(result, parsedModule{
				file:   key,
				entity: Entity{Domain: domain.Name, Type: "library", ID: libID, Field: "rego"},
				module: m,
			})
		}
	}
	return result
}

// checkModuleGroup compiles a group of modules together and returns diagnostics.
func checkModuleGroup(modules []parsedModule, regoOffsets map[string]map[string]int) []Diagnostic {
	if len(modules) == 0 {
		return nil
	}

	parsed := make(map[string]*ast.Module, len(modules))
	for _, pm := range modules {
		parsed[fmt.Sprintf("%s:%s", pm.entity.Type, pm.entity.ID)] = pm.module
	}

	compiler := ast.NewCompiler()
	compiler.Compile(parsed)
	if !compiler.Failed() {
		return nil
	}

	return convertCompilerErrors(compiler.Errors, modules, regoOffsets)
}

// checkPoliciesWithDeps checks each policy together with its resolved library deps.
func checkPoliciesWithDeps(models []*policydomain.IntermediateModel, domainKeyMap map[string]string, reg *registry.Registry, opts ast.ParserOptions, regoOffsets map[string]map[string]int) []Diagnostic {
	var diagnostics []Diagnostic
	domains := reg.GetDomains()

	for _, domain := range models {
		key := domainKeyMap[domain.Name]

		for policyID, policy := range domain.Policies {
			if strings.TrimSpace(policy.Rego) == "" {
				continue
			}

			moduleID := fmt.Sprintf("policy:%s", policyID)
			m, err := ast.ParseModuleWithOpts(moduleID, policy.Rego, opts)
			if err != nil {
				continue // parse errors captured elsewhere
			}

			group := []parsedModule{{
				file:   key,
				entity: Entity{Domain: domain.Name, Type: "policy", ID: policyID, Field: "rego"},
				module: m,
			}}

			// Resolve and add library dependencies
			resolvedDeps, err := reg.ResolveDependencies(domain, policy.Dependencies)
			if err == nil {
				for _, depRef := range resolvedDeps {
					depDomainName, depLibID := parseDependencyRef(depRef, domain.Name)
					depDomain := domains[depDomainName]
					if depDomain == nil {
						continue
					}
					if lib, ok := depDomain.PolicyLibraries[depLibID]; ok && strings.TrimSpace(lib.Rego) != "" {
						libModuleID := fmt.Sprintf("library:%s", depLibID)
						libM, err := ast.ParseModuleWithOpts(libModuleID, lib.Rego, opts)
						if err == nil {
							group = append(group, parsedModule{
								file:   domainKeyMap[depDomainName],
								entity: Entity{Domain: depDomainName, Type: "library", ID: depLibID, Field: "rego"},
								module: libM,
							})
						}
					}
				}
			}

			diagnostics = append(diagnostics, checkModuleGroup(group, regoOffsets)...)
		}
	}

	return diagnostics
}

// checkMappers checks each mapper individually.
func checkMappers(models []*policydomain.IntermediateModel, domainKeyMap map[string]string, opts ast.ParserOptions, regoOffsets map[string]map[string]int) []Diagnostic {
	var diagnostics []Diagnostic

	for _, domain := range models {
		key := domainKeyMap[domain.Name]

		for i, mapper := range domain.Mappers {
			if strings.TrimSpace(mapper.Rego) == "" {
				continue
			}
			mapperID := mapper.IDSpec.ID
			if mapperID == "" {
				mapperID = mapperFallbackID(i)
			}
			moduleID := fmt.Sprintf("mapper:%s", mapperID)
			m, err := ast.ParseModuleWithOpts(moduleID, mapper.Rego, opts)
			if err != nil {
				continue
			}
			group := []parsedModule{{
				file:   key,
				entity: Entity{Domain: domain.Name, Type: "mapper", ID: mapperID, Field: "rego"},
				module: m,
			}}
			diagnostics = append(diagnostics, checkModuleGroup(group, regoOffsets)...)
		}
	}

	return diagnostics
}

// convertCompilerErrors converts ast.Errors from the OPA compiler to Diagnostics.
// It matches each error back to the source entity via the module name embedded
// in the error's Location.File field.
func convertCompilerErrors(errs ast.Errors, modules []parsedModule, regoOffsets map[string]map[string]int) []Diagnostic {
	byID := make(map[string]parsedModule, len(modules))
	for _, pm := range modules {
		byID[fmt.Sprintf("%s:%s", pm.entity.Type, pm.entity.ID)] = pm
	}

	var diagnostics []Diagnostic
	for _, astErr := range errs {
		moduleID := ""
		if astErr.Location != nil {
			moduleID = astErr.Location.File
		}

		pm, found := byID[moduleID]
		if !found {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceOPACheck,
				Severity: SeverityError,
				Message:  astErr.Message,
				Category: astErr.Code,
			})
			continue
		}

		d := Diagnostic{
			Source:   SourceOPACheck,
			Severity: SeverityError,
			Location: Location{File: pm.file},
			Entity:   pm.entity,
			Message:  astErr.Message,
			Category: astErr.Code,
		}

		if astErr.Location != nil && astErr.Location.Row > 0 {
			var offset int
			if fileOffsets := regoOffsets[pm.file]; fileOffsets != nil {
				offset = fileOffsets[pm.entity.Type+":"+pm.entity.ID]
			}
			if offset > 0 {
				d.Location.Start.Line = offset + astErr.Location.Row - 1
			} else {
				d.Location.Start.Line = astErr.Location.Row
			}
			d.Location.Start.Column = astErr.Location.Col
			d.RegoOffset = offset
		}

		diagnostics = append(diagnostics, d)
	}

	return diagnostics
}

// parseDependencyRef splits "domain/libraryID" or just "libraryID".
func parseDependencyRef(ref, currentDomain string) (string, string) {
	if idx := strings.Index(ref, "/"); idx >= 0 {
		return ref[:idx], ref[idx+1:]
	}
	return currentDomain, ref
}
