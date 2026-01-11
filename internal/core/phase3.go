//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"
	"time"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

/********************************************************************************************
 * Phase3 evaluates policies related to resource in the PORC context.
 ********************************************************************************************/
type phase3 struct {
	phase
}

// phase3 is executed only if prior resource resolution is successful. ie, either group is provided in PORC or resource
// MRN is used to fully resolve the resource in "input"
func (p3 *phase3) exec(ctx context.Context, pe *PolicyEngine, input map[string]interface{}) bool {
	phaseStart := time.Now()
	defer func() {
		p3.duration = safeNanos(time.Since(phaseStart))
	}()

	var (
		result       bool
		perr         *common.PolicyError
		policy       *model.Policy
		evalDuration uint64
	)

	// ResourceGroup policy check
	logger.Tracef(agent, "authorize", "[phase3] Resource: %+v", input[resource])

	res := input[resource].(*model.Resource)
	rg, perr := pe.backend.GetResourceGroup(ctx, res.Group)
	if perr != nil {
		logger.Debugf(agent, "authorize", "[phase3] error getting group for resource %s (err: %+v)", res.ID, perr)
	} else {
		policy = rg.Policy
		evalStart := time.Now()
		result, perr = rg.Policy.EvaluateBool(ctx, input)
		evalDuration = safeNanos(time.Since(evalStart))
		if perr != nil {
			logger.Debugf(agent, "authorize", "[phase3] phase3 failed(err-%s)", perr)
		}
	}

	desc := events.AccessRecord_DENY
	if result {
		desc = events.AccessRecord_GRANT
	}
	p3.append(buildBundleReference(perr, policy, events.AccessRecord_BundleReference_RESOURCE, res.Group, desc, evalDuration))

	return result
}
