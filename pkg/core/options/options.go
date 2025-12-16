//
//  Copyright © Manetu Inc. All rights reserved.
//
// shared between pkg/core and internal/core, and thus must be in a separate package to avoid circular dependencies

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

// EngineOptions defines the configuration options for initializing a policy engine, including factories for access logs and backends.
type EngineOptions struct {
	AccessLogFactory accesslog.Factory
	BackendFactory   backend.Factory
	CompilerOptions  []opa.CompilerOptionFunc
}

// EngineOptionsFunc is a function that modifies EngineOptions.
type EngineOptionsFunc func(*EngineOptions)

// WithAccessLog configures the access log stream for the engine.
func WithAccessLog(factory accesslog.Factory) EngineOptionsFunc {
	return func(o *EngineOptions) {
		o.AccessLogFactory = factory
	}
}

// WithBackend configures the backend factory for the engine.
func WithBackend(factory backend.Factory) EngineOptionsFunc {
	return func(o *EngineOptions) {
		if config.VConfig.GetBool(config.MockEnabled) {
			logger.Warn(agent, "WithBackend", "Ignoring backend factory as mock mode is enabled")
		} else {
			o.BackendFactory = factory
		}
	}
}

// WithCompilerOptions configures the OPA compiler options for the engine.
func WithCompilerOptions(opts ...opa.CompilerOptionFunc) EngineOptionsFunc {
	return func(o *EngineOptions) {
		o.CompilerOptions = opts
	}
}

// AuthzOptions represents configuration options for Authorize operations.
type AuthzOptions struct {
	Probe bool
}

// AuthzOptionsFunc is a function that modifies AuthzOptions.
type AuthzOptionsFunc func(*AuthzOptions)

// SetProbeMode configures the probe mode for Authorize operations.  Probe mode evaluates policies but does not
// log decisions, which is helpful for returning information about what capabilities a user/service has without impacting
// the audit trail.  For instance, if you want to show a UI user whether they can modify a resource, you can run Authorize
// in probe mode as if they have tried to modify the resource, using the decision outcome in the display.  However,
// it would be unfair to generate an audit record that suggests that the user tried to modify the resource, when really
// your service was merely testing to see if they could.
//
// Probe mode is disabled by default. Use with caution and only in places where you are sure that the decision doesn't
// require logging.
func SetProbeMode(probe bool) AuthzOptionsFunc {
	return func(o *AuthzOptions) {
		o.Probe = probe
	}
}
