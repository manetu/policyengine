//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"
	"sync"
	"time"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

/********************************************************************************************
 * Phase4 evaluates policies related to scopes in the PORC context.
 ********************************************************************************************/

const (
	apiScope = "mrn:iam:scope:api"
)

type phase4 struct {
	phase
}

func (p4 *phase4) exec(ctx context.Context, pe *PolicyEngine, principalMap map[string]interface{}, input map[string]interface{}) bool {
	phaseStart := time.Now()
	defer func() {
		p4.duration = safeNanos(time.Since(phaseStart))
	}()

	logger.Trace(agent, "authorize", "proceeding to phase4")
	scs := []string{}
	for _, s := range toStringSlice(principalMap[Scopes]) {
		if s == apiScope {
			logger.Trace(agent, "authorize", "[phase4] found api scope...auth allowed")
			//NOTE: we are NOT adding a bundleReference for this
			return true
		}

		scs = append(scs, s)
	}

	if len(scs) == 0 {
		logger.Trace(agent, "authorize", "[phase4] no scopes")
		//NOTE: we are NOT adding a bundleReference for this
		return true
	}

	logger.Tracef(agent, "authorize", "[phase4] processing scopes %+v", scs)

	numScopes := len(scs)

	policies := make([]*model.Policy, numScopes)
	decs := make([]bool, numScopes)
	errs := make([]*common.PolicyError, numScopes)
	durations := make([]uint64, numScopes)

	// ------------ begin processing policies concurrently ---------------
	wg := sync.WaitGroup{}
	wg.Add(numScopes)

	// check other apis OR with realm policies
	for ind, s := range scs {
		go func(i int, scopeMrn string) {
			defer wg.Done()

			scope, err := pe.backend.GetScope(ctx, scopeMrn)
			if err != nil {
				// errors will be logged below and decs[i] will default to false
				errs[i] = err
				return
			}

			policies[i] = scope.Policy
			evalStart := time.Now()
			decs[i], errs[i] = scope.Policy.EvaluateBool(ctx, input)
			durations[i] = safeNanos(time.Since(evalStart))
		}(ind, s)
	}

	wg.Wait()

	//log results from phase4 for each role
	for i := 0; i < numScopes; i++ {
		if errs[i] != nil {
			logger.Debugf(agent, "authorize", "[phase4] failed for scope [%s](err-%s)", scs[i], errs[i])
		} else {
			logger.Debugf(agent, "authorize", "[phase4] result for scope [%s](result-%t)", scs[i], decs[i])
		}
	}

	result := false
	for i := 0; i < numScopes; i++ {
		desc := events.AccessRecord_DENY
		if decs[i] {
			logger.Debugf(agent, "authorize", "[phase4] succeeded for scope [%s]", scs[i])
			result = true
			desc = events.AccessRecord_GRANT
		}

		p4.append(buildBundleReference(errs[i], policies[i], events.AccessRecord_BundleReference_SCOPE, scs[i], desc, durations[i]))
	}

	return result
}
