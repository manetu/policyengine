//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"os"

	"github.com/manetu/policyengine/internal/core/accesslog"
	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// NewTestPolicyEngine - instantiates a PE suitable for unit-testing
func NewTestPolicyEngine(depth int) (core.PolicyEngine, chan *events.AccessRecord, error) {
	err := os.Setenv(config.ConfigPathEnv, "..") // relative to caller, not this code
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan *events.AccessRecord, depth)
	engine, err := core.NewPolicyEngine(
		options.WithAccessLog(accesslog.NewChannelLogger(ch)),
	)
	if err != nil {
		return nil, nil, err
	}

	return engine, ch, nil
}
