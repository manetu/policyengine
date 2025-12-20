//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package options provides configuration types and functional options for the
// policy engine and authorization operations.
//
// This package uses the functional options pattern to provide a clean,
// extensible API for configuring the policy engine and individual authorization
// calls.
//
// # Engine Options
//
// Engine options configure the policy engine at initialization time:
//
//	pe, err := core.NewPolicyEngine(
//	    options.WithBackend(local.NewFactory(registry)),
//	    options.WithAccessLog(kafka.NewFactory()),
//	    options.WithCompilerOptions(opa.WithRegoVersion(ast.RegoV1)),
//	)
//
// # Authorization Options
//
// Authorization options configure individual Authorize calls:
//
//	// Enable probe mode to evaluate policies without logging
//	allowed, err := pe.Authorize(ctx, porc, options.SetProbeMode(true))
//
// # Available Options
//
// Engine configuration:
//   - [WithBackend]: Configure the policy storage backend
//   - [WithAccessLog]: Configure the access log destination
//   - [WithCompilerOptions]: Configure OPA compiler settings
//
// Authorization configuration:
//   - [SetProbeMode]: Enable/disable probe mode for capability discovery
package options

import (
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/opa"
)

var logger = logging.GetLogger("policyengine")
var agent = "policyengine"

// EngineOptions holds the configuration for initializing a [core.PolicyEngine].
//
// EngineOptions is typically not created directly. Instead, use the functional
// option functions like [WithBackend] and [WithAccessLog] when calling
// [core.NewPolicyEngine].
//
// Fields:
//   - AccessLogFactory: Creates the stream for audit logging (default: stdout)
//   - BackendFactory: Creates the policy storage backend (default: mock)
//   - CompilerOptions: OPA compiler configuration (default: RegoV0, standard capabilities)
type EngineOptions struct {
	AccessLogFactory accesslog.Factory
	BackendFactory   backend.Factory
	CompilerOptions  []opa.CompilerOptionFunc
}

// EngineOptionsFunc is a functional option for configuring [EngineOptions].
//
// Functions of this type are passed to [core.NewPolicyEngine] to customize
// the engine's configuration. See [WithBackend], [WithAccessLog], and
// [WithCompilerOptions] for available options.
type EngineOptionsFunc func(*EngineOptions)

// WithAccessLog configures the access log factory for the policy engine.
//
// The access log records all authorization decisions for audit purposes.
// Built-in factories include:
//   - [accesslog.NewStdoutFactory]: Writes JSON records to stdout (default)
//   - [accesslog.NewNullFactory]: Discards all records (useful for testing)
//
// Example:
//
//	pe, err := core.NewPolicyEngine(
//	    options.WithAccessLog(accesslog.NewStdoutFactory()),
//	)
func WithAccessLog(factory accesslog.Factory) EngineOptionsFunc {
	return func(o *EngineOptions) {
		o.AccessLogFactory = factory
	}
}

// WithBackend configures the policy storage backend for the engine.
//
// The backend is responsible for loading and serving policy data including
// roles, scopes, operations, resource groups, and policies. Built-in backends:
//   - [backend/local.NewFactory]: Loads policies from local YAML files
//   - Mock backend: Used by default for testing (no explicit factory needed)
//
// Note: If mock mode is enabled via configuration (MPE_MOCK_ENABLED=true),
// this option is ignored and a warning is logged.
//
// Example:
//
//	registry, _ := registry.NewRegistry([]string{"./policies"})
//	pe, err := core.NewPolicyEngine(
//	    options.WithBackend(local.NewFactory(registry)),
//	)
func WithBackend(factory backend.Factory) EngineOptionsFunc {
	return func(o *EngineOptions) {
		if config.VConfig.GetBool(config.MockEnabled) {
			logger.Warn(agent, "WithBackend", "Ignoring backend factory as mock mode is enabled")
		} else {
			o.BackendFactory = factory
		}
	}
}

// WithCompilerOptions configures the OPA compiler for policy evaluation.
//
// Compiler options control how Rego policies are parsed and compiled.
// Available options from the [opa] package include:
//   - [opa.WithRegoVersion]: Set the Rego language version (V0 or V1)
//   - [opa.WithCapabilities]: Set OPA capabilities
//   - [opa.WithUnsafeBuiltins]: Disable specific built-in functions for security
//   - [opa.WithDefaultTracing]: Enable trace output during evaluation
//
// Example:
//
//	pe, err := core.NewPolicyEngine(
//	    options.WithCompilerOptions(
//	        opa.WithRegoVersion(ast.RegoV1),
//	        opa.WithDefaultTracing(true),
//	    ),
//	)
func WithCompilerOptions(opts ...opa.CompilerOptionFunc) EngineOptionsFunc {
	return func(o *EngineOptions) {
		o.CompilerOptions = opts
	}
}

// AuthzOptions holds configuration for individual authorization calls.
//
// AuthzOptions is typically not created directly. Instead, use functional
// options like [SetProbeMode] when calling [core.PolicyEngine.Authorize].
//
// Fields:
//   - Probe: When true, evaluates policies without logging to the access log
type AuthzOptions struct {
	Probe bool
}

// AuthzOptionsFunc is a functional option for configuring [AuthzOptions].
//
// Functions of this type are passed to [core.PolicyEngine.Authorize] to
// customize the authorization behavior. See [SetProbeMode] for available options.
type AuthzOptionsFunc func(*AuthzOptions)

// SetProbeMode configures probe mode for authorization operations.
//
// Probe mode evaluates policies without logging decisions to the access log.
// This is useful for capability discovery scenarios where you need to determine
// what a user can do without creating audit trail entries.
//
// # Use Case: UI Capability Display
//
// Consider a UI that shows whether a user can edit a document. You want to
// display an "Edit" button only if the user has permission. Using probe mode:
//
//	canEdit, _ := pe.Authorize(ctx, porc, options.SetProbeMode(true))
//	if canEdit {
//	    showEditButton()
//	}
//
// Without probe mode, this would create an audit record suggesting the user
// attempted to edit the document, which would be misleading.
//
// # Important Considerations
//
// Probe mode is disabled by default. Use it only when:
//   - You are checking capabilities for UI/UX purposes
//   - The check should not appear in audit logs
//   - You are not making an actual access attempt
//
// For actual access attempts, always use normal mode (probe=false) to maintain
// a complete audit trail.
func SetProbeMode(probe bool) AuthzOptionsFunc {
	return func(o *AuthzOptions) {
		o.Probe = probe
	}
}
