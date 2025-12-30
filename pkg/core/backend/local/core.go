//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package local provides a backend implementation that loads policies
// from local YAML files via a [registry.Registry].
//
// The local backend is the standard backend for applications that
// manage their policies as configuration files, either bundled with
// the application or loaded from a filesystem path.
//
// # Usage
//
//	// Load policy domains from local directories
//	registry, err := registry.NewRegistry([]string{
//	    "./policies/base",
//	    "./policies/application",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create policy engine with local backend
//	pe, err := core.NewPolicyEngine(
//	    options.WithBackend(local.NewFactory(registry)),
//	)
//
// # Policy Compilation
//
// When [Backend] is created via [Factory.NewBackend], all policies and
// mappers in the registry are compiled. This ensures fast authorization
// decisions at runtime with no compilation overhead.
package local

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/manetu/policyengine/pkg/policydomain/validation"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

var logger = logging.GetLogger("policyengine.backend.local")
var actor = "backend.local"

// Factory creates [Backend] instances from a [registry.Registry].
type Factory struct {
	reg *registry.Registry
}

// Backend implements [backend.Service] using policy domain data from a registry.
//
// Backend serves policy data from compiled policy domains. All policies and
// mappers are compiled during backend initialization, ensuring fast runtime
// performance.
type Backend struct {
	policyCompiler *opa.Compiler
	mapperCompiler *opa.Compiler
	reg            *registry.Registry
}

// NewFactory creates a [backend.Factory] for the local backend.
//
// The registry must be fully loaded and validated before calling NewFactory.
// Use [registry.NewRegistry] to create the registry from policy domain paths.
func NewFactory(reg *registry.Registry) backend.Factory {
	return &Factory{reg: reg}
}

// NewBackend creates a [Backend] and compiles all policies in the registry.
//
// The provided compiler is used for policies (with unsafe built-in exclusions).
// A separate mapper compiler is created with default capabilities since mappers
// may need access to built-ins that are restricted for policies.
//
// Returns an error if any policy or mapper fails to compile.
func (f *Factory) NewBackend(compiler *opa.Compiler) (backend.Service, error) {
	// Create a separate OPA compiler for mappers, since they don't want/need unsafe builtin exclusions like the policy compiler does
	mapperCompiler := compiler.Clone(opa.WithDefaultCapabilities())

	// Compile all policies and mappers upfront using the backend's compilers.
	// This ensures trace logging and Rego V1 compatibility settings are respected.
	if err := f.reg.CompileAllPolicies(compiler, mapperCompiler); err != nil {
		return nil, err
	}

	return &Backend{
		policyCompiler: compiler,
		mapperCompiler: mapperCompiler,
		reg:            f.reg,
	}, nil
}

func newTestBackend(compiler *opa.Compiler, reg *registry.Registry) *Backend {
	return &Backend{
		policyCompiler: compiler,
		mapperCompiler: compiler,
		reg:            reg,
	}
}

func toRichAnnotations(input map[string]policydomain.Annotation) (model.RichAnnotations, *common.PolicyError) {
	if input == nil {
		return nil, nil
	}
	output := make(model.RichAnnotations, len(input))
	for k, av := range input {
		var x interface{}
		err := json.Unmarshal([]byte(av.Value), &x)
		if err != nil {
			return nil, &common.PolicyError{
				ReasonCode: events.AccessRecord_BundleReference_INVALPARAM_ERROR,
				Reason:     fmt.Sprintf("bad annotation '%s' (err-%s)", k, err.Error()),
			}
		}
		output[k] = model.AnnotationEntry{
			Value:         x,
			MergeStrategy: av.MergeStrategy,
		}
	}
	return output, nil
}

func (b *Backend) policyRefExport(ref *policydomain.PolicyReference) (*model.PolicyReference, *common.PolicyError) {
	annotations, err := toRichAnnotations(ref.Annotations)
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
	}

	policy, err := b.getPolicy(ref.Policy)
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
	}

	return &model.PolicyReference{
		Mrn:         ref.IDSpec.ID,
		Policy:      policy,
		Annotations: annotations,
	}, nil
}

// getPolicy retrieves a policy by MRN from the cached intermediate model.
// Policies are pre-compiled during backend initialization, so this is a simple lookup.
func (b *Backend) getPolicy(mrn string) (*model.Policy, *common.PolicyError) {
	logger.Tracef(actor, "Get", "getPolicy: mrn %v", mrn)

	// Search all domains for the policy
	for _, domainModel := range b.reg.GetDomains() {
		if policy, ok := domainModel.Policies[mrn]; ok {
			// Policy is already compiled at backend initialization time
			if policy.Ast == nil {
				return nil, common.NewError(events.AccessRecord_BundleReference_COMPILATION_ERROR,
					fmt.Sprintf("policy %s has no compiled AST", mrn))
			}

			return &model.Policy{
				Mrn:         policy.IDSpec.ID,
				Fingerprint: policy.IDSpec.Fingerprint,
				Ast:         policy.Ast,
			}, nil
		}
	}

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "policy not found")
}

// GetResource retrieves a resource by MRN with RichAnnotations for merge support.
// First checks for matches in PolicyDomain::Resources definition (v1alpha4+),
// then falls back to using the ResourceGroup designated with default=true.
// RichAnnotations automatically flatten to plain values when serialized to JSON for OPA.
func (b *Backend) GetResource(ctx context.Context, mrn string) (*model.Resource, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetResource: %v", mrn)

	// First, search all domains for a Resource that matches the MRN using selectors
	for _, domainModel := range b.reg.GetDomains() {
		for _, resource := range domainModel.Resources {
			for _, selector := range resource.Selectors {
				if selector.MatchString(mrn) {
					// Found a matching resource definition
					richAnnotations, err := toRichAnnotations(resource.Annotations)
					if err != nil {
						return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
					}

					return &model.Resource{
						ID:          mrn,
						Group:       resource.Group,
						Annotations: richAnnotations,
					}, nil
				}
			}
		}
	}

	// No explicit resource match found, fall back to default resource group
	var defaultResourceGroup string
	for _, domainModel := range b.reg.GetDomains() {
		for rgMrn, rg := range domainModel.ResourceGroups {
			if rg.Default {
				defaultResourceGroup = rgMrn
				break
			}
		}
		if defaultResourceGroup != "" {
			break
		}
	}

	if defaultResourceGroup == "" {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "no matching resource and no default resource group found")
	}

	return &model.Resource{
		ID:    mrn,
		Group: defaultResourceGroup,
	}, nil
}

// GetResourceGroup retrieves a resource group by MRN from any domain
func (b *Backend) GetResourceGroup(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetResourceGroup: %v", mrn)

	// Search all domains for the resource group
	var rgRef *policydomain.PolicyReference
	found := false

	for _, domainModel := range b.reg.GetDomains() {
		if ref, ok := domainModel.ResourceGroups[mrn]; ok {
			rgRef = &ref
			found = true
			break
		}
	}

	if !found {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "resource group not found")
	}

	return b.policyRefExport(rgRef)
}

// GetRole retrieves a role by MRN from any domain
func (b *Backend) GetRole(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetRole: %v", mrn)

	// Search all domains for the role
	var roleRef *policydomain.PolicyReference
	found := false

	for _, domainModel := range b.reg.GetDomains() {
		if ref, ok := domainModel.Roles[mrn]; ok {
			roleRef = &ref
			found = true
			break
		}
	}

	if !found {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "role not found")
	}

	return b.policyRefExport(roleRef)
}

// GetScope retrieves a scope by MRN from any domain
func (b *Backend) GetScope(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetScope: %v", mrn)

	// Search all domains for the scope
	var scopeRef *policydomain.PolicyReference
	found := false

	for _, domainModel := range b.reg.GetDomains() {
		if ref, ok := domainModel.Scopes[mrn]; ok {
			scopeRef = &ref
			found = true
			break
		}
	}

	if !found {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "scope not found")
	}

	return b.policyRefExport(scopeRef)
}

// GetGroup retrieves a group by MRN from any domain
func (b *Backend) GetGroup(ctx context.Context, mrn string) (*model.Group, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetGroup: %v", mrn)

	// Search all domains for the group
	var group *policydomain.Group
	found := false

	for _, domainModel := range b.reg.GetDomains() {
		if g, ok := domainModel.Groups[mrn]; ok {
			group = &g
			found = true
			break
		}
	}

	if !found {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "group not found")
	}

	annotations, err := toRichAnnotations(group.Annotations)
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
	}
	return &model.Group{
		Mrn:         group.IDSpec.ID,
		Roles:       group.Roles,
		Annotations: annotations,
	}, nil
}

// GetOperation retrieves an operation by MRN and returns its associated policy reference.
func (b *Backend) GetOperation(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	logger.Tracef(actor, "Get", "GetOperation: %v", mrn)

	// Use common library to find object across domains
	domainMapAdapter := registry.NewDomainMapAdapter(b.reg.GetDomains())
	resolver := validation.NewReferenceResolver(domainMapAdapter)

	foundDomainName, _, err := resolver.FindObjectAcrossDomains(mrn, "operation")
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "operation not found")
	}

	// Convert back to domain.Model for compatibility with existing logic
	domain := b.reg.GetDomains()[foundDomainName]

	// Find the matching operation in that domain
	for _, operation := range domain.Operations {
		for _, selector := range operation.Selectors {
			if selector.MatchString(mrn) {
				// Use common library for reference resolution
				targetDomain, _, policyID, err := resolver.ResolveReference(operation.Policy, foundDomainName, "policy")
				if err != nil {
					return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
				}

				// Convert back to access the policy
				targetDomainModel := b.reg.GetDomains()[targetDomain]
				policy, ok := targetDomainModel.Policies[policyID]
				if !ok {
					return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, "internal model corruption")
				}

				policyModel, perr := b.getPolicy(policy.IDSpec.ID)
				if perr != nil {
					return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, err.Error())
				}

				return &model.PolicyReference{
					Mrn:    operation.IDSpec.ID,
					Policy: policyModel,
				}, nil
			}
		}
	}

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "operation not found")
}

// exportMapper converts a cached intermediate mapper to a frontend model mapper.
// Mappers are pre-compiled during backend initialization.
func (b *Backend) exportMapper(domainName string, mapper *policydomain.Mapper) (*model.Mapper, *common.PolicyError) {
	if mapper.Ast == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_COMPILATION_ERROR,
			fmt.Sprintf("mapper %s has no compiled AST", mapper.IDSpec.ID))
	}

	return &model.Mapper{
		Domain: domainName,
		Ast:    mapper.Ast,
	}, nil
}

// GetMapper retrieves the mapper from the specified domain or the first available mapper.
// Mappers are pre-compiled during backend initialization, so this is a simple lookup.
func (b *Backend) GetMapper(ctx context.Context, domainName string) (*model.Mapper, *common.PolicyError) {
	if domainName != "" {
		// User specified a domain name
		domainModel, exists := b.reg.GetDomains()[domainName]
		if !exists || domainModel == nil {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("domain '%s' not found", domainName))
		}

		if len(domainModel.Mappers) == 0 {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("no mappers found in domain '%s'", domainName))
		}

		if len(domainModel.Mappers) > 1 {
			return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, fmt.Sprintf("multiple mappers found in domain '%s', this is not supported", domainName))
		}

		return b.exportMapper(domainName, &domainModel.Mappers[0])
	}

	// No domain specified, find the first mapper across all domains
	var foundMapper *policydomain.Mapper
	var foundDomain string
	mapperCount := 0

	for currentDomainName, domainModel := range b.reg.GetDomains() {
		if len(domainModel.Mappers) > 0 {
			mapperCount += len(domainModel.Mappers)
			if foundMapper == nil {
				foundMapper = &domainModel.Mappers[0]
				foundDomain = currentDomainName
			}
		}
	}

	if foundMapper == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "no mappers found in any domain")
	}

	if mapperCount > 1 {
		return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, "multiple mappers found across domains, please specify a domain name using --name/-n")
	}

	return b.exportMapper(foundDomain, foundMapper)
}
