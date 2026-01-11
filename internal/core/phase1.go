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

/*************************************************************************************
 * phase1 is sometimes called “SYSTEM” or “OPERATION” phase…it is a policy driven by the
 * “operation” field in the PORC and is unique in that its the only policy that executes
 * with a tri-state result. The tri-state is helpful for special cases where the other
 * phases might not be able to work properly. For example, consider the following
 *    1. some operations might be “public” and thus do not necessarily carry a JWT
 *    2. some operations might be “visitor” and use RECAPTCHA tokens rather than JWTs
 *    3. other operations might require a JWT
 * Tri-state allows phase1 to make all the decisions (GRANT/DENY) or let the other phases
 * decide.
 ************************************************************************************/

type phase1 struct {
	phase
	result int
}

func getPolicyForOperation(ctx context.Context, pe *PolicyEngine, mrn string) (*model.Policy, *common.PolicyError) {
	op, err := pe.backend.GetOperation(ctx, mrn)
	if err != nil {
		return nil, err
	}

	return op.Policy, nil
}

// phase1 returns a tri-state result - -1, 0 or > 0.
//
//	 -1 is a DENY
//	 > 0 is a GRANT
//	for the entire policy evaluation. Rest of the phases are ignored.
//
// Value 0 is an leaves the result to be computed from the evaluation of other phases.
func (p1 *phase1) exec(ctx context.Context, pe *PolicyEngine, input map[string]interface{}, op string) events.AccessRecord_Decision {
	phaseStart := time.Now()
	defer func() {
		p1.duration = safeNanos(time.Since(phaseStart))
	}()

	var (
		result       events.AccessRecord_Decision
		perr         *common.PolicyError
		policy       *model.Policy
		evalDuration uint64
	)

	result = events.AccessRecord_UNSPECIFIED
	bundleResult := events.AccessRecord_DENY

	policy, perr = getPolicyForOperation(ctx, pe, op)
	if perr != nil || policy == nil {
		logger.Debugf(agent, "authorize", "[phase1] no main policy (err-%s)", perr)

		p1.result = -1
		result = events.AccessRecord_DENY
	} else {
		logger.Debugf(agent, "authorize", "[phase1] got policy: %+v", policy)

		evalStart := time.Now()
		p1.result, perr = policy.EvaluateInt(ctx, input)
		evalDuration = safeNanos(time.Since(evalStart))

		if perr != nil {
			result = events.AccessRecord_DENY
			logger.Debugf(agent, "authorize", "[phase1] failed(err-%s)", perr)
		} else {
			if logger.IsDebugEnabled() {
				logger.Debugf(agent, "authorize", "[phase1] result: %d", p1.result)
			}

			if p1.result > 0 {
				result = events.AccessRecord_GRANT
				bundleResult = events.AccessRecord_GRANT
			} else if p1.result < 0 {
				result = events.AccessRecord_DENY
			} else {
				bundleResult = events.AccessRecord_GRANT
			}
		}
	}

	p1.append(buildBundleReference(perr, policy, events.AccessRecord_BundleReference_SYSTEM, op, bundleResult, evalDuration))

	return result
}
