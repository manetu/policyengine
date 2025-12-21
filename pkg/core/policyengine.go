//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package core provides the primary interface for the Manetu Policy Engine,
// an authorization system that evaluates access control decisions based on
// PORC (Principal, Operation, Resource, Context) inputs.
//
// The Policy Engine implements a multi-phase evaluation model that processes
// roles, scopes, operations, and resource groups to produce authorization
// decisions. Each decision can optionally be logged to an access log for
// audit trail purposes.
//
// # Quick Start
//
// Create a policy engine with default options (stdout access log, mock backend):
//
//	pe, err := core.NewPolicyEngine()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Make an authorization decision:
//
//	allowed, err := pe.Authorize(ctx, `{
//	    "principal": {
//	        "sub": "alice@example.com",
//	        "mroles": ["mrn:iam:role:editor"]
//	    },
//	    "operation": "api:documents:read",
//	    "resource": "mrn:app:document:12345",
//	    "context": {}
//	}`)
//
// # Configuration
//
// The engine supports various configuration options via functional options:
//
//	pe, err := core.NewPolicyEngine(
//	    options.WithBackend(local.NewFactory(registry)),
//	    options.WithAccessLog(accesslog.NewStdoutFactory()),
//	)
//
// # Probe Mode
//
// For UI capabilities discovery without impacting audit logs, use probe mode:
//
//	allowed, err := pe.Authorize(ctx, porc, options.SetProbeMode(true))
//
// See the [options] package for all available configuration options.
package core

import (
	"context"

	"github.com/manetu/policyengine/internal/core"
	"github.com/manetu/policyengine/internal/core/backend/mock"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/backend/local"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/core/types"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/pkg/errors"
)

var logger = logging.GetLogger("policyengine")
var agent = "policyengine"

// PolicyEngine is the primary interface for making authorization decisions.
//
// PolicyEngine evaluates access control requests by processing PORC
// (Principal, Operation, Resource, Context) inputs through a multi-phase
// policy evaluation pipeline. The engine supports pluggable backends for
// policy storage and access logs for audit trails.
//
// Implementations of PolicyEngine are safe for concurrent use by multiple
// goroutines.
type PolicyEngine interface {
	// Authorize evaluates an authorization request and returns the decision.
	//
	// The porc parameter accepts either a JSON string or a map[string]interface{}
	// representing the PORC structure. See the [types] package for details.
	//
	// Returns true if the request is authorized, false otherwise.
	// Returns an error if the PORC is malformed or evaluation fails.
	Authorize(ctx context.Context, porc types.AnyPORC, authzOptions ...options.AuthzOptionsFunc) (bool, error)

	// GetBackend returns the underlying backend service used for policy retrieval.
	//
	// This is useful for advanced use cases where direct access to policy data
	// is needed, such as debugging or policy introspection.
	GetBackend() backend.Service
}

// PolicyEngineImpl is the default implementation of the [PolicyEngine] interface.
//
// PolicyEngineImpl wraps the internal policy engine implementation and can be
// embedded or wrapped by applications that need to extend or customize the
// engine's behavior, such as adding context management or middleware.
//
// Use [NewPolicyEngine] to create a properly initialized instance.
type PolicyEngineImpl struct {
	instance core.PolicyEngine
}

// NewPolicyEngine creates and initializes a new [PolicyEngine] instance.
//
// By default, the engine uses a stdout access log and a mock backend.
// Use functional options to configure a production backend and access log:
//
//	pe, err := core.NewPolicyEngine(
//	    options.WithBackend(local.NewFactory(registry)),
//	    options.WithAccessLog(kafka.NewFactory()),
//	    options.WithCompilerOptions(opa.WithRegoVersion(ast.RegoV1)),
//	)
//
// NewPolicyEngine loads configuration from environment variables and config
// files before initializing the engine. See the [config] package for details.
//
// Returns an error if configuration loading fails or if the backend cannot
// be initialized.
func NewPolicyEngine(engineOptions ...options.EngineOptionsFunc) (PolicyEngine, error) {
	err := config.Load()
	if err != nil {
		return nil, errors.Wrap(err, "error loading config")
	}

	opts := &options.EngineOptions{
		AccessLogFactory: accesslog.NewStdoutFactory(),
		BackendFactory:   mock.NewFactory(),
	}
	for _, o := range engineOptions {
		o(opts)
	}

	instance, err := core.NewPolicyEngine(opts)
	if err != nil {
		return nil, err
	}

	return &PolicyEngineImpl{
		instance: *instance,
	}, nil
}

// NewLocalPolicyEngine creates and initializes a new [PolicyEngine] instance
// from local policydomain files.
//
// Each domainPath should be a file containing a policy domain YAML file
// (policydomain.yaml or similar). Domains are loaded in the order provided,
// with later domains taking precedence for name collisions.
//
// Other defaults are inherited from [NewPolicyEngine].
//
// Use functional options to configure a production backend and access log:
//
//	pe, err := core.NewLocalPolicyEngine(policydomains,
//	    options.WithAccessLog(kafka.NewFactory()),
//	    options.WithCompilerOptions(opa.WithRegoVersion(ast.RegoV1)),
//	)
//
// Returns an error if configuration loading fails or if the backend cannot
// be initialized.
func NewLocalPolicyEngine(domainPaths []string, engineOptions ...options.EngineOptionsFunc) (PolicyEngine, error) {
	err := config.Load()
	if err != nil {
		return nil, errors.Wrap(err, "error loading config")
	}

	r, err := registry.NewRegistry(domainPaths)
	if err != nil {
		return nil, err
	}

	engineOptions = append(engineOptions, options.WithBackend(local.NewFactory(r)))
	return NewPolicyEngine(engineOptions...)
}

// Authorize evaluates an authorization request and returns the decision.
//
// The porc parameter can be provided as either:
//   - A JSON string containing the PORC structure
//   - A map[string]interface{} with the PORC fields already unmarshalled
//
// The PORC structure must contain principal, operation, resource, and context
// fields. See the [types] package for the expected structure.
//
// Authorization options can modify the evaluation behavior:
//
//	// Enable probe mode to skip access logging
//	allowed, err := pe.Authorize(ctx, porc, options.SetProbeMode(true))
//
// The authorization decision and any evaluation errors are logged to the
// configured access log (unless probe mode is enabled).
func (pe *PolicyEngineImpl) Authorize(ctx context.Context, porc types.AnyPORC, authzOptions ...options.AuthzOptionsFunc) (bool, error) {
	logger.Debug(agent, "Authorize", "Enter")
	defer logger.Debug(agent, "Authorize", "Exit")

	opts := &options.AuthzOptions{Probe: false}
	for _, o := range authzOptions {
		o(opts)
	}

	input, err := types.UnmarshalPORC(porc)
	if err != nil {
		return false, err
	}

	authz := pe.instance.Authorize(ctx, input, opts)
	logger.Debugf(agent, "Authorize", "returned from authorize(): %t", authz)

	return authz, nil
}

// GetBackend returns the backend service used by this policy engine.
//
// The backend service provides access to policy data including roles, scopes,
// operations, and resource groups. This method is primarily intended for
// advanced use cases such as policy introspection or debugging.
func (pe *PolicyEngineImpl) GetBackend() backend.Service {
	return pe.instance.GetBackend()
}
