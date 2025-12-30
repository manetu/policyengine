//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package backend defines the interfaces for policy storage backends.
//
// A backend is responsible for storing and retrieving policy domain data
// including roles, groups, scopes, operations, resources, and policies.
// The policy engine uses backends to load the data needed for authorization
// decisions.
//
// # Built-in Backends
//
// The following backend implementations are available:
//   - [local]: Loads policies from local YAML files via a [registry.Registry]
//   - Mock backend (internal): Returns empty data, useful for testing
//
// # Implementing a Custom Backend
//
// To implement a custom backend (e.g., for a database or remote service):
//
//  1. Implement the [Factory] interface to create backend instances
//  2. Implement the [Service] interface to provide policy data
//  3. Use the backend with [options.WithBackend] when creating the engine
//
// Example:
//
//	type MyFactory struct { /* ... */ }
//
//	func (f *MyFactory) NewBackend(c *opa.Compiler) (backend.Service, error) {
//	    return &MyBackend{compiler: c}, nil
//	}
//
//	// Use with policy engine
//	pe, _ := core.NewPolicyEngine(options.WithBackend(&MyFactory{}))
//
// # MRN Format
//
// All methods that accept MRN (Manetu Resource Name) parameters expect
// identifiers in the format: mrn:<domain>:<type>:<path>
// For example: mrn:example:role:admin
package backend

import (
	"context"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
)

// Factory creates backend [Service] instances.
//
// The factory pattern separates early initialization (configuration defaults,
// resource allocation) from late initialization (connecting to services,
// compiling policies). The policy engine framework guarantees:
//
//  1. Factory construction happens early, allowing Viper defaults to be set
//  2. Configuration is fully loaded before [NewBackend] is called
//  3. The OPA [Compiler] is initialized and passed to [NewBackend]
//
// Implementations should perform expensive operations (database connections,
// policy compilation) in [NewBackend], not during factory construction.
type Factory interface {
	// NewBackend creates a new backend service instance.
	//
	// The provided compiler should be used to compile any Rego policies.
	// This method is called after configuration is fully loaded.
	//
	// Returns an error if the backend cannot be initialized (e.g., database
	// connection failure, policy compilation error).
	NewBackend(*opa.Compiler) (Service, error)
}

// Service provides access to policy domain data for authorization decisions.
//
// Service methods retrieve policy-related entities by their MRN (Manetu Resource
// Name). Each method returns the requested entity and a [common.PolicyError] if
// the entity is not found or cannot be retrieved.
//
// All methods are safe for concurrent use by multiple goroutines.
//
// # Error Handling
//
// Methods return *[common.PolicyError] instead of error to provide structured
// error information including reason codes suitable for access logging.
// A nil PolicyError indicates success.
type Service interface {
	// GetRole retrieves a role by its MRN.
	//
	// Roles define sets of permissions that can be assigned to principals.
	// The returned PolicyReference includes the role's associated policy AST.
	GetRole(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)

	// GetGroup retrieves a group by its MRN.
	//
	// Groups are collections of roles that can be assigned to principals,
	// providing a convenient way to manage permissions for multiple users.
	GetGroup(ctx context.Context, mrn string) (*model.Group, *common.PolicyError)

	// GetScope retrieves a scope by its MRN.
	//
	// Scopes define policy boundaries that limit where permissions apply.
	GetScope(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)

	// GetResource retrieves a resource by its MRN.
	//
	// Resources are the targets of operations. If no explicit resource
	// definition matches, the default resource group is used.
	// Returns the resource with RichAnnotations to support annotation merging.
	// When serialized to JSON for OPA, RichAnnotations automatically flatten
	// to plain values.
	GetResource(ctx context.Context, mrn string) (*model.Resource, *common.PolicyError)

	// GetResourceGroup retrieves a resource group by its MRN.
	//
	// Resource groups organize resources and define default policies
	// for resources that don't have explicit definitions.
	GetResourceGroup(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)

	// GetOperation retrieves an operation by its MRN.
	//
	// Operations define actions that can be performed on resources
	// (e.g., read, write, delete) and their associated policies.
	GetOperation(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)

	// GetMapper retrieves the mapper for a policy domain.
	//
	// Mappers transform external identity claims into PORC principal data.
	// If domainName is empty, returns the mapper from the first domain
	// that has one (error if multiple domains have mappers).
	GetMapper(ctx context.Context, domainName string) (*model.Mapper, *common.PolicyError)
}
