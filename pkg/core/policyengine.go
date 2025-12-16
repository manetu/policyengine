//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"

	"github.com/manetu/policyengine/internal/core"
	"github.com/manetu/policyengine/internal/core/backend/mock"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/core/types"
	"github.com/pkg/errors"
)

var logger = logging.GetLogger("policyengine")
var agent = "policyengine"

// PolicyEngine represents a public Policy Engine instance, suitable for use by clients
type PolicyEngine interface {
	Authorize(ctx context.Context, porc types.AnyPORC, authzOptions ...options.AuthzOptionsFunc) (bool, error)
}

// PolicyEngineImpl implements the PolicyEngine interface, suitable for wrapping for context management, etc
type PolicyEngineImpl struct {
	instance core.PolicyEngine
}

// NewPolicyEngine creates a new PolicyEngine instance
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

// Authorize returns an authorization decision for the provided PORC
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
