//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package registry provides functionality for loading and validating
// policy domains from YAML files.
//
// The registry is the primary entry point for loading policy domains.
// It parses YAML files, validates cross-references, and compiles Rego
// policies into executable ASTs.
//
// # Loading Policy Domains
//
//	registry, err := registry.NewRegistry([]string{
//	    "./policies/domain1",
//	    "./policies/domain2",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Using with the Policy Engine
//
//	backend := local.NewFactory(registry)
//	pe, _ := core.NewPolicyEngine(options.WithBackend(backend))
//
// # Validation
//
// The registry validates all cross-references between policy entities
// during loading. Use [Registry.ValidateWithSummary] for detailed error
// information, or [Registry.GetAllValidationErrors] for programmatic access.
package registry

import (
	"crypto/sha256"
	"fmt"

	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/parsers"
	"github.com/manetu/policyengine/pkg/policydomain/validation"
)

// DomainMap maps policy domain names to their parsed intermediate models.
type DomainMap map[string]*policydomain.IntermediateModel

// Registry manages loaded policy domains and their validation state.
//
// Registry is created by [NewRegistry], which loads and validates policy
// domain YAML files. The registry can then be used with the local backend
// to provide policy data to the engine.
type Registry struct {
	domains   DomainMap
	validator *validation.BundleValidator
}

func reverse[T any](list []T) []T {
	for i, j := 0, len(list)-1; i < j; {
		list[i], list[j] = list[j], list[i]
		i++
		j--
	}
	return list
}

func (r *Registry) verify() error {
	return r.validator.ValidateAll()
}

// ValidateWithSummary validates and returns a detailed summary of any errors
func (r *Registry) ValidateWithSummary() (bool, string) {
	return r.validator.ValidateWithSummary()
}

// GetAllValidationErrors returns all validation errors without stopping on first error
func (r *Registry) GetAllValidationErrors() []*validation.Error {
	return r.validator.GetAllValidationErrors()
}

// ValidateDomain validates a specific domain and returns detailed errors
func (r *Registry) ValidateDomain(domainName string) error {
	return r.validator.ValidateDomain(domainName)
}

// GetDomains returns the domain map for accessing domain models
func (r *Registry) GetDomains() DomainMap {
	return r.domains
}

// ResolveDependencies resolves dependencies for a domain model
func (r *Registry) ResolveDependencies(model *policydomain.IntermediateModel, dependencies []string) ([]string, error) {
	// Create adapter for this specific model
	modelAdapter := &DomainModelAdapter{model}

	// Use common library's dependency resolution
	return r.validator.ValidateDependencies(modelAdapter, dependencies)
}

// NewRegistry loads and validates policy domains from the specified paths.
//
// Each path should be a directory containing a policy domain YAML file
// (policydomain.yaml or similar). Domains are loaded in the order provided,
// with later domains taking precedence for name collisions.
//
// Returns an error if any domain fails to parse or validate.
//
// Example:
//
//	registry, err := registry.NewRegistry([]string{
//	    "./policies/base",
//	    "./policies/application",
//	})
func NewRegistry(domainPaths []string) (*Registry, error) {
	domainsList := make([]*policydomain.IntermediateModel, 0)
	for _, domainpath := range domainPaths {
		instance, err := parsers.Load(domainpath)
		if err != nil {
			return nil, err
		}
		domainsList = append(domainsList, instance)
	}

	domains := make(map[string]*policydomain.IntermediateModel)
	for _, instance := range reverse(domainsList) {
		domains[instance.Name] = instance
	}

	// Create adapter for the common validation library
	domainMapAdapter := NewDomainMapAdapter(domains)

	// Use the common validation library
	validator := validation.NewBundleValidator(domainMapAdapter)

	r := &Registry{
		domains:   domains,
		validator: validator, // Only need common lib validator
	}

	if err := r.verify(); err != nil {
		return nil, err
	}
	return r, nil
}

// CompileAllPolicies compiles all policies and mappers in all domains, caching the ASTs.
// This should be called after registry creation with the compiler from the backend.
// The policyCompiler is used for policies (with unsafe builtin exclusions).
// The mapperCompiler is used for mappers (with default capabilities).
func (r *Registry) CompileAllPolicies(policyCompiler *opa.Compiler, mapperCompiler *opa.Compiler) error {
	for domainName, domain := range r.domains {
		// Compile all policies
		if err := r.compilePoliciesInDomain(policyCompiler, domain); err != nil {
			return fmt.Errorf("domain %s: %w", domainName, err)
		}

		// Compile all mappers
		if err := r.compileMappersInDomain(mapperCompiler, domain); err != nil {
			return fmt.Errorf("domain %s: %w", domainName, err)
		}
	}
	return nil
}

// compilePoliciesInDomain compiles all policies in a domain
func (r *Registry) compilePoliciesInDomain(compiler *opa.Compiler, domain *policydomain.IntermediateModel) error {
	// Compile policy libraries first (they may be dependencies)
	for mrn, policy := range domain.PolicyLibraries {
		if policy.Ast != nil {
			continue // Already compiled
		}
		ast, err := r.compilePolicyWithDeps(compiler, domain, &policy)
		if err != nil {
			return fmt.Errorf("policy library %s: %w", mrn, err)
		}
		policy.Ast = ast
		domain.PolicyLibraries[mrn] = policy
	}

	// Compile policies
	for mrn, policy := range domain.Policies {
		if policy.Ast != nil {
			continue // Already compiled
		}
		ast, err := r.compilePolicyWithDeps(compiler, domain, &policy)
		if err != nil {
			return fmt.Errorf("policy %s: %w", mrn, err)
		}
		policy.Ast = ast
		domain.Policies[mrn] = policy
	}

	return nil
}

// compilePolicyWithDeps compiles a policy with its dependencies
func (r *Registry) compilePolicyWithDeps(compiler *opa.Compiler, sourceDomain *policydomain.IntermediateModel, policy *policydomain.Policy) (*opa.Ast, error) {
	mrn := policy.IDSpec.ID

	// Build module map with policy and all dependencies
	modules := map[string]string{}
	modules[mrn] = policy.Rego

	// Compute fingerprint from all rego code
	h := sha256.New()
	h.Write([]byte(mrn))
	h.Write([]byte(policy.Rego))

	// Resolve and add dependencies
	deps, err := r.ResolveDependencies(sourceDomain, policy.Dependencies)
	if err != nil {
		return nil, fmt.Errorf("resolving dependencies: %w", err)
	}

	domainMapAdapter := NewDomainMapAdapter(r.domains)
	resolver := validation.NewReferenceResolver(domainMapAdapter)

	for _, dmrn := range deps {
		targetDomainName, _, depID, resolveErr := resolver.ResolveReference(dmrn, sourceDomain.Name, "library")
		if resolveErr != nil {
			return nil, fmt.Errorf("resolving reference %s: %w", dmrn, resolveErr)
		}

		targetDomain := r.domains[targetDomainName]
		dep, ok := targetDomain.PolicyLibraries[depID]
		if !ok {
			return nil, fmt.Errorf("library %s not found in domain %s", depID, targetDomainName)
		}

		h.Write([]byte(dep.Rego))
		modules[dep.IDSpec.ID] = dep.Rego
	}

	// Update fingerprint
	policy.IDSpec.Fingerprint = h.Sum(nil)

	// Compile
	ast, err := compiler.Compile(mrn, modules)
	if err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}

	return ast, nil
}

// compileMappersInDomain compiles all mappers in a domain
func (r *Registry) compileMappersInDomain(compiler *opa.Compiler, domain *policydomain.IntermediateModel) error {
	for i := range domain.Mappers {
		mapper := &domain.Mappers[i]
		if mapper.Ast != nil {
			continue // Already compiled
		}

		modules := map[string]string{}
		modules[mapper.IDSpec.ID] = mapper.Rego

		ast, err := compiler.Compile(mapper.IDSpec.ID, modules)
		if err != nil {
			return fmt.Errorf("mapper %s: compilation failed: %w", mapper.IDSpec.ID, err)
		}

		mapper.Ast = ast
	}

	return nil
}
