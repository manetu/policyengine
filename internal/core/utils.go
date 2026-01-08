//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"strings"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/model"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

func getUnsafeBuiltins() map[string]struct{} {
	builtins := strings.Split(config.VConfig.GetString(config.UnsafeBuiltIns), ",")
	m := make(map[string]struct{})
	for _, f := range builtins {
		m[f] = struct{}{}
	}

	return m
}

func buildBundleReference(policyError *common.PolicyError, policy *model.Policy, phase events.AccessRecord_BundleReference_Phase, id string, result events.AccessRecord_Decision, duration uint64) *events.AccessRecord_BundleReference {
	var policies []*events.AccessRecord_PolicyReference

	event := &events.AccessRecord_PolicyReference{}
	if policy != nil {
		event.Mrn = policy.Mrn
		event.Fingerprint = policy.Fingerprint
	}
	policies = append(policies, event)

	br := &events.AccessRecord_BundleReference{
		Id:       id,
		Policies: policies,
		Phase:    phase,
		Duration: duration,
	}

	// error trumps everything
	if policyError != nil {
		br.Decision = events.AccessRecord_DENY
		br.ReasonCode = policyError.ReasonCode
		br.Reason = policyError.Reason
	} else {
		br.Decision = result
	}

	return br
}
