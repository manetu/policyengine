//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

/************************************************************************************
 * Phase2 is the "identity" phase where decision depends on the roles, groups and other
 * aspects of identity derived from the PORC. The policies corresponding to the identity
 * are used to evaluate the request in the context of the PORC.
 *************************************************************************************/

type phase2 struct {
	phase
}

func (p2 *phase2) exec(ctx context.Context, pe *PolicyEngine, principalMap map[string]interface{}, input map[string]interface{}) bool {
	logger.Trace(agent, "authorize", "proceeding to phase2")

	var policies []*model.Policy

	roleMap := make(map[string]interface{})
	if rs, ok := principalMap[Mroles].([]interface{}); ok {
		for _, x := range rs {
			var r string
			r, _ = x.(string)
			roleMap[r] = struct{}{}
		}
	}

	if groups, ok := principalMap[Mgroups].([]interface{}); ok {
		logger.Tracef(agent, "authorize", "[phase2] input groups %+v", groups)
		// if fetching a group fails, record it but keep going. If there are no roles,
		// we will DENY phase2. We just need one GRANT from the processing of policies
		// for any one of roles
		for _, x := range groups {
			var (
				groupMrn string
			)
			groupMrn, _ = x.(string)
			group, perr := pe.backend.GetGroup(ctx, groupMrn)
			if perr != nil {
				logger.Tracef(agent, "authorize", "[phase2] get rolebundle failed for group %s", groupMrn)
				p2.append(buildBundleReference(perr, nil, events.AccessRecord_BundleReference_IDENTITY, groupMrn, events.AccessRecord_DENY))
			} else {
				for _, r := range group.Roles {
					roleMap[r] = struct{}{}
				}
			}
		}
	}

	logger.Tracef(agent, "authorize", "[phase2] processing rolemap %+v", roleMap)

	rs := slices.Collect(maps.Keys(roleMap))

	policies = make([]*model.Policy, len(rs))
	decs := make([]bool, len(rs))
	errs := make([]*common.PolicyError, len(rs))

	// ------------ begin processing policies concurrently ---------------
	numRoles := len(rs)

	wg := sync.WaitGroup{}
	wg.Add(numRoles)

	// check other apis OR with realm policies
	for ind, roleMrn := range rs {
		go func(i int, roleMrn string) {
			defer wg.Done()

			role, err := pe.backend.GetRole(ctx, roleMrn)
			if err != nil {
				// errors will be logged below and decs[i] will default to false
				errs[i] = err
				return
			}

			policies[i] = role.Policy
			decs[i], errs[i] = role.Policy.EvaluateBool(ctx, input)
		}(ind, roleMrn)
	}

	wg.Wait()

	//log results from phase2 for each role
	for i := 0; i < numRoles; i++ {
		if errs[i] != nil {
			logger.Debugf(agent, "authorize", "[phase2] failed for role [%s](err-%s)", rs[i], errs[i])
		} else {
			logger.Debugf(agent, "authorize", "[phase2] result for role [%s](result-%t)", rs[i], decs[i])
		}
	}

	// result is ORed from all GRANTs... but create bundle references for all for audit and display purposes
	result := false
	for i := 0; i < numRoles; i++ {
		desc := events.AccessRecord_DENY
		if decs[i] {
			logger.Debugf(agent, "authorize", "[phase2] succeeded for role [%s]", rs[i])
			result = true
			desc = events.AccessRecord_GRANT
		}

		p2.append(buildBundleReference(errs[i], policies[i], events.AccessRecord_BundleReference_IDENTITY, rs[i], desc))
	}

	return result
}
