//
//  Copyright © Manetu Inc. All rights reserved.
//

package core_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/manetu/policyengine/internal/core/test"
	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/core/types"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/stretchr/testify/assert"
)

func createPE(t *testing.T, opa string) (chan *events.AccessRecord, core.PolicyEngine) {
	pe, ch, err := test.NewTestPolicyEngine(1024)
	assert.Nil(t, err)
	assert.NotNil(t, pe)
	assert.NotNil(t, ch)

	if opa != "" {
		config.VConfig.Set("mock.domain.filedata.main.rego", opa)
	}

	return ch, pe
}

// NOTE: this should be deprecated (at least not called for entities with more than 1 element)... use getBundleRefById instead
func getBundleRef(record *events.AccessRecord, ph events.AccessRecord_BundleReference_Phase, num int) *events.AccessRecord_BundleReference {
	n := 0
	for _, r := range record.References {
		if r.Phase == ph {
			if n == num {
				return r
			}
			n++
		}
	}

	return nil
}

func getBundleRefById(record *events.AccessRecord, ph events.AccessRecord_BundleReference_Phase, id string) *events.AccessRecord_BundleReference {
	for _, r := range record.References {
		if r.Phase == ph {
			if r.Id == id {
				return r
			}
		}
	}

	return nil
}
func TestAuditDecision(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../..")
	config.ResetConfig()
	ctx := context.Background()

	// NOTE: refer to mpe-config.yaml.
	var auditDecisionTests = []struct {
		name string
		opa  string
		porc string
		wrap bool
		pre  func()
		post func(pe core.PolicyEngine, decision bool, record *events.AccessRecord)

		//results
		shldErr bool
		errmsg  string
	}{
		{
			name: "always succeed for admin role (antilockout phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:admin"],
			           "scopes": ["mrn:iam:scope:myscope"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, s-known scope
				// expected result:
				//    decision: GRANT (antilockout)
				//    phase:    SYSTEM
				//    reasonCode:  POLICY_OUTCOME

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				assert.True(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				assert.Equal(t, record.OverrideReason.(*events.AccessRecord_GrantReason).GrantReason, events.AccessRecord_ANTI_LOCKOUT)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 4, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)
			},
		},

		{
			name: "bad porc (fail in phase1)",
			wrap: false,
			porc: `{"principal": {},
                                 "resource":"mrn:vault:bar:v1",
                                 "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-no jwt, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY
				//    phase:    SYSTEM
				//    reasonCode:  POLICY_OUTCOME

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				assert.True(t, record.SystemOverride)
				assert.Equal(t, events.AccessRecord_DENY, record.Decision)
				assert.Equal(t, events.AccessRecord_JWT_REQUIRED, record.OverrideReason.(*events.AccessRecord_DenyReason).DenyReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 2, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase1Ref.Decision)
			},
			shldErr: false,
			errmsg:  "The caller does not have permission",
		},
		{
			name: "succeed (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
                       "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["mrn:iam:scope:myscope"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANT (antilockout)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, after evaulating non-existing resource
				//    SCOPE    - GRANT, scope in our mock policy with all allowed

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 4, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				// although resource is not defined in our system, default RG will be attached
				// with successful resource policy outcome
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)

				phase4Ref := getBundleRef(record, events.AccessRecord_BundleReference_SCOPE, 0)
				assert.NotNil(t, phase4Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase4Ref.ReasonCode)
				assert.Equal(t, "", phase4Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase4Ref.Decision)
			},
		},
		{
			name: "fail (post phase1) - scope not found",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["badscope"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (phase4 failure)
				//    phase:    post-SYSTEM
				//    outcome:  NOT_FOUND
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, after evaulating non-existing resource
				//    SCOPE    - DENY, no such scope

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 4, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				// although resource is not defined in our system, default RG will be attached
				// with successful resource policy outcome
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)

				phase4Ref := getBundleRef(record, events.AccessRecord_BundleReference_SCOPE, 0)
				assert.NotNil(t, phase4Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_NOTFOUND_ERROR, phase4Ref.ReasonCode)
				assert.Equal(t, events.AccessRecord_DENY, phase4Ref.Decision)
			},
		},
		{
			name: "superadmin succeed (post phase 1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:superadmin"]},
			           "resource":"mrn:realm:realm",
			           "operation":"platform:realm:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANT (post phase1)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, after evaulating non-existing resource
				//    SCOPE    - GRANT, scope in our mock policy with all allowed

				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				// although resource is not defined in our system, default RG will be attached
				// with successful resource policy outcome
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)
			},
		},
		{
			name: "superadmin fail (post phase 1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:superadmin"]},
			           "resource":"mrn:realm:realm",
			           "operation":"realm:realm:write"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (post phase1)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - DENY, invalid op for PO
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision) //super admin cannot create realm
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase2Ref.ReasonCode)
			},
		},
		{
			name: "need superadmin, fail (in phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:admin"]},
			           "resource":"mrn:realm:realm",
			           "operation":"platform:realm:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good jwt, r-unknown resource, o-known op
				// expected result:
				//    decision: DENY (phase1)
				//    phase:    SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				assert.False(t, decision)
				assert.NotNil(t, record)
				assert.True(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				assert.Equal(t, record.OverrideReason.(*events.AccessRecord_DenyReason).DenyReason, events.AccessRecord_OPERATOR_REQUIRED)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase1Ref.Decision)
			},
		},
		{
			name: "succeed with no scopes(post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"bar",
			           "aud":"manetu.io",
			           "mroles":["mrn:iam:role:myrole"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANT (post phase 1)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, after evaulating non-existing resource
				//    SCOPE    - GRANT, scope in our mock policy with all allowed

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				// although resource is not defined in our system, default RG will be attached
				// with successful resource policy outcome
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)
			},
		},
		{
			name: "failed role evaluation (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "LOW",
			           "mroles":["mrn:iam:role:unknown"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (role not found)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - DENY, role NOT_FOUND

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_NOTFOUND_ERROR, phase2Ref.ReasonCode)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)
			},
		},
		{
			name: "granted getting one successful role (post phase1)",
			wrap: false,
			porc: `{"principal":
                                  {"sub":"foo",
                                   "mrealm":"acme",
                                   "aud":"manetu.io",
                                   "mclearance": "MAXIMUM",
                                   "mroles":["mrn:iam:role:myrole", "mrn:iam:role:notfound"]},
                                   "resource":"mrn:vault:bar:v1",
                                   "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANTED (network error on policy but another role succeeded)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role found and evaluated successfully

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 4, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:role:notfound")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "role not found 3: mrn:iam:role:notfound", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)

				phase2Ref = getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:role:myrole")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision)
			},
		},
		{
			name: "failed group evaluation (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "LOW",
			           "mgroups":["mrn:iam:group:unknown"]},
			           "resource":"mrn:vault:bar:v1",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (group not found)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - DENY, group NOT_FOUND

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_NOTFOUND_ERROR, phase2Ref.ReasonCode)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)
			},
		},
		{
			name: "granted getting one successful group (post phase1)",
			wrap: false,
			porc: `{"principal":
                                  {"sub":"foo",
                                   "mrealm":"acme",
                                   "aud":"manetu.io",
                                   "mclearance": "MAXIMUM",
                                   "mgroups":["mrn:iam:group:mygroup", "mrn:iam:group:notfound"]},
                                   "resource":"mrn:vault:bar:v1",
                                   "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANTED (network error on policy but another role succeeded)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, group found and evaluated successfully

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 5, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:group:notfound")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "group not found: mrn:iam:group:notfound", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)

				phase2Ref = getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:role:myrole")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision)
			},
		},
		{
			name: "granted getting one successful role (post phase1), even when all groups fail",
			wrap: false,
			porc: `{"principal":
                                  {"sub":"foo",
                                   "mrealm":"acme",
                                   "aud":"manetu.io",
                                   "mclearance": "MAXIMUM",
                                   "mgroups":["mrn:iam:group:notfound1", "mrn:iam:group:notfound2"],
                                   "mroles":["mrn:iam:role:myrole", "mrn:iam:role:notfound"]},
                                   "resource":"mrn:vault:bar:v1",
                                   "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: GRANTED (network error on policy but another role succeeded)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, group found and evaluated successfully

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 6, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:role:notfound")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "role not found 3: mrn:iam:role:notfound", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)

				phase2Ref = getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:group:notfound1")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "group not found: mrn:iam:group:notfound1", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)

				phase2Ref = getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:group:notfound2")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "group not found: mrn:iam:group:notfound2", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase2Ref.Decision)

				phase2Ref = getBundleRefById(record, events.AccessRecord_BundleReference_IDENTITY, "mrn:iam:role:myrole")
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, "", phase2Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision)
			},
		},
		{
			name: "failed resource clearance policy (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "LOW",
			           "mroles":["mrn:iam:role:myrole"]},
			           "resource":"mrn:vault:acme:resource:sharedresource",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (resource failed)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - DENY, LOW clearance

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase3Ref.Decision)
			},
		},
		{
			name: "failed resource network error (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "LOW",
			           "mroles":["mrn:iam:role:myrole"]},
			           "resource":"mrn:iam:resource:networkerror",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (resource failed)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    RESOURCE - DENY, network error on getting resource

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_NETWORK_ERROR, phase3Ref.ReasonCode)
				assert.Equal(t, record.Resource, "mrn:iam:resource:networkerror")
				assert.Equal(t, phase3Ref.Id, "mrn:iam:resource:networkerror")
			},
		},
		{
			name: "failed resource with bad annotations error (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "LOW",
			           "mroles":["mrn:iam:role:myrole"]},
			           "resource":"mrn:vault:acme:resource:badannotation",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (resource failed)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    RESOURCE - DENY, invalid param due to bad annotations

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_INVALPARAM_ERROR, phase3Ref.ReasonCode)
				assert.Contains(t, phase3Ref.Reason, "bad annotation")
				assert.Equal(t, record.Resource, "mrn:vault:acme:resource:badannotation")
				assert.Equal(t, phase3Ref.Id, "mrn:vault:acme:resource:badannotation")
			},
		},
		{
			name: "succeed resource clearance policy (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "MAXIMUM",
			           "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["mrn:iam:scope:api"]},
			           "resource":"mrn:vault:acme:resource:sharedresource",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (antilockout)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, MAXIMUM clearance
				//    SCOPE    - GRANT, api scope

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)
			},
		},
		{
			name: "failed bad scope (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "MAXIMUM",
			           "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["mrn:iam:acme:scope:networkerror"]},
			           "resource":"mrn:vault:acme:resource:sharedresource",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (antilockout)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, MAXIMUM clearance
				//    SCOPE    - DENY, error on one scope

				//------------- check overall decision ----------------
				assert.False(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_DENY)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 4, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)
			},
		},
		{
			name: "succeeded with 1 good scop (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "MAXIMUM",
			           "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["mrn:iam:scope:myscope", "mrn:iam:acme:scope:notfound"]},
			           "resource":"mrn:vault:acme:resource:sharedresource",
			           "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (antilockout)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, MAXIMUM clearance
				//    SCOPE    - GRANT, error on one scope, good on another

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 5, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)

				phase4Ref := getBundleRefById(record, events.AccessRecord_BundleReference_SCOPE, "mrn:iam:scope:myscope")
				assert.NotNil(t, phase4Ref)
				assert.Equal(t, "", phase4Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase4Ref.Decision)

				phase4Ref = getBundleRefById(record, events.AccessRecord_BundleReference_SCOPE, "mrn:iam:acme:scope:notfound")
				assert.NotNil(t, phase4Ref)
				assert.Equal(t, "scopes not found: mrn:iam:acme:scope:notfound", phase4Ref.Reason)
				assert.Equal(t, events.AccessRecord_DENY, phase4Ref.Decision)
			},
		},
		{
			name: "succeed with pre-resolved resource (post phase1)",
			wrap: false,
			porc: `{"principal":
			          {"sub":"foo",
			           "mrealm":"acme",
			           "aud":"manetu.io",
			           "mclearance": "MAXIMUM",
			           "mroles":["mrn:iam:role:myrole"],
			           "scopes": ["mrn:iam:scope:api"]},
			        "resource": {"id": "mrn:vault:acme:resource:sharedresource",
                                 "group": "mrn:iam:resource-group:sharedresourcegroup",
								 "classification": "HIGH",
                                 "annotations": {"foo": "bar", "extnnot": {"a": "aaa", "i": 100}}},
			        "operation":"vault:admin:create"}`,
			post: func(pe core.PolicyEngine, decision bool, record *events.AccessRecord) {
				// summary for p-good, r-unknown resource, o-known op, s-known scope
				// expected result:
				//    decision: DENY (antilockout)
				//    phase:    post-SYSTEM
				//    reasonCode:  POLICY_OUTCOME
				//  Other bundles:
				//    IDENTITY - GRANT, role in our mock policy with all allowed
				//    RESOURCE - GRANT, MAXIMUM clearance
				//    SCOPE    - GRANT, api scope

				//------------- check overall decision ----------------
				assert.True(t, decision)
				assert.NotNil(t, record)
				// not system decision
				assert.False(t, record.SystemOverride)
				assert.Equal(t, record.Decision, events.AccessRecord_GRANT)
				// not set when !system-result (not phase1 grant)
				assert.Nil(t, record.OverrideReason)

				// ----------- check bundle reference ... should jive with decision -------------
				assert.Equal(t, 3, len(record.References))

				phase1Ref := getBundleRef(record, events.AccessRecord_BundleReference_SYSTEM, 0)
				assert.NotNil(t, phase1Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase1Ref.ReasonCode)
				assert.Equal(t, "", phase1Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase1Ref.Decision)

				phase2Ref := getBundleRef(record, events.AccessRecord_BundleReference_IDENTITY, 0)
				assert.NotNil(t, phase2Ref)
				assert.Equal(t, events.AccessRecord_GRANT, phase2Ref.Decision) //admin role not in our poliy (though passed in SYSTEM)

				phase3Ref := getBundleRef(record, events.AccessRecord_BundleReference_RESOURCE, 0)
				assert.NotNil(t, phase3Ref)
				assert.Equal(t, events.AccessRecord_BundleReference_POLICY_OUTCOME, phase3Ref.ReasonCode)
				assert.Equal(t, "", phase3Ref.Reason)
				assert.Equal(t, events.AccessRecord_GRANT, phase3Ref.Decision)

				porkJ, err := types.UnmarshalPORC(record.Porc)
				assert.Nil(t, err)
				r, ok := porkJ["resource"].(map[string]interface{})
				assert.True(t, ok)
				assert.NotNil(t, r)
				assert.Equal(t, r["annotations"], map[string]interface{}{"extnnot": map[string]interface{}{"a": "aaa", "i": float64(100)}, "foo": "bar"})
			},
		},
	}

	for _, test := range auditDecisionTests {
		t.Run(test.name, func(t *testing.T) {
			if test.pre != nil {
				test.pre()
			}

			accessLogger, pe := createPE(t, test.opa)
			authz, err := pe.Authorize(ctx, test.porc)
			if test.shldErr {
				assert.Error(t, err)
				if test.errmsg != "" {
					assert.Contains(t, err.Error(), test.errmsg)
				}
			} else {
				assert.NoError(t, err)
			}
			m := <-accessLogger
			if test.post != nil {
				test.post(pe, authz, m)
			}
		})
	}
}
func TestNoToken(t *testing.T) {
	ctx := context.Background()
	porc := "{\"principal\":{\"sub\":\"foo\",\"mrealm\":\"bar\",\"aud\":\"manetu.io\",\"mroles\":[\"USER\"]}}"

	pe, _, err := test.NewTestPolicyEngine(1024)
	assert.Nil(t, err)

	config.VConfig.Set("mock.domain.filedata.main.rego", opasimple)

	authz, _ := pe.Authorize(ctx, porc)
	assert.True(t, authz)
}

func TestNoTokenNoPrincipal(t *testing.T) {
	ctx := context.Background()

	porc := "{\"principal\":\"nobody\"}"

	pe, _, err := test.NewTestPolicyEngine(1024)

	config.VConfig.Set("mock.domain.filedata.main.rego", opasimple)

	assert.Nil(t, err)
	authz, _ := pe.Authorize(ctx, porc)
	assert.True(t, authz)
	authz, _ = pe.Authorize(ctx, porc)
	assert.True(t, authz)
	authz, _ = pe.Authorize(ctx, porc)
	assert.True(t, authz)
	authz, _ = pe.Authorize(ctx, porc)
	assert.True(t, authz)

	time.Sleep(2 * time.Second)
}

func BenchmarkDecistion(b *testing.B) {
	porc := "{\"principal\":\"nobody\"}"
	pe, _, _ := test.NewTestPolicyEngine(1024)
	ctx := context.Background()

	config.VConfig.Set("mock.domain.filedata.main.rego", opasimple)

	for n := 0; n < b.N; n++ {
		_, _ = pe.Authorize(ctx, porc)
	}
}

func TestConcurrentPORC(t *testing.T) {
	config.VConfig.Set(config.MockEnabled, true)

	ctx := context.Background()
	porc := `{"principal":
                    {"sub":"foo",
                     "mrealm":"bar",
                     "aud":"manetu.io",
                     "mroles":["mrn:iam:role:admin"]},
                 "resource":"mrn:vault:bar:v1",
                 "operation":"vault:admin:create",
                 "scopes": ["mrn:iam:scope:myscope"]}`

	pe, _, _ := test.NewTestPolicyEngine(1024)
	wg := &sync.WaitGroup{}
	wg.Add(100)
	for n := 0; n < 100; n++ {
		go func(i int) {
			defer wg.Done()
			authz, _ := pe.Authorize(ctx, porc)
			assert.True(t, true, authz)
		}(n)
	}
	wg.Wait()
}

// TestConcurrentPolicyEngineInit tests that multiple PolicyEngine instances can be created
// concurrently without race conditions. This simulates what happens when multiple unit tests
// run in parallel, each initializing their own PolicyEngine.
// Run with: go test -race -run TestConcurrentPolicyEngineInit
func TestConcurrentPolicyEngineInit(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../..")
	config.ResetConfig()

	const numGoroutines = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	engines := make([]core.PolicyEngine, numGoroutines)
	errors := make([]error, numGoroutines)

	// Spawn multiple goroutines that all create PolicyEngine instances concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			pe, _, err := test.NewTestPolicyEngine(1024)
			engines[idx] = pe
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify all engines were created successfully
	for i := 0; i < numGoroutines; i++ {
		assert.Nil(t, errors[i], "Engine %d should not have an error", i)
		assert.NotNil(t, engines[i], "Engine %d should not be nil", i)
	}
}

func TestDisallowHttpSend(t *testing.T) {
	var (
		listener net.Listener
		err      error
		ch       chan error
	)

	defer func() {
		if listener != nil {
			_ = listener.Close()
		}
	}()

	// create an http server to avoid false positive transport level errors
	ch = make(chan error)
	go func() {
		//list on any port
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			ch <- err
			return
		}

		ch <- nil

		_ = http.Serve(listener, nil)
	}()

	err = <-ch
	assert.Nil(t, err)

	config.VConfig.Set(config.MockEnabled, true)

	config.VConfig.Set("mock.domain.filedata.main.rego", fmt.Sprintf(opahttpsend, listener.Addr().String()))

	pe, _, _ := test.NewTestPolicyEngine(1024)
	ctx := context.Background()

	porc := "{\"principal\":{\"sub\":\"foo\",\"mrealm\":\"bar\",\"aud\":\"manetu.io\",\"mroles\":[\"mrn:iam:role:admin\"]},\"resource\":\"mrn:http:/manetu.api.localfile.v1.IAMGateway/CreateRole\",\"operation\":\"http:post\", \"scopes\": [\"mrn:iam:scope:myscope\"]}"
	authz, _ := pe.Authorize(ctx, porc)
	// NOTE: though not surfaced, we do see the error log that confirms the unsafebuiltins is kicking in...
	//      {"action":"compileBundle","actor":"policyengine","level":"error","module":"policyengine","msg":"error compiling modules: 1 error occurred: mrn:iam:policy:main:6: rego_type_error: unsafe built-in function calls in expression: http.send","time":"2024-02-09T12:52:56-05:00"}
	assert.False(t, authz)

	//turn unsafebuiltins and try again
	config.VConfig.SetDefault(config.UnsafeBuiltIns, "")
	pe, _, _ = test.NewTestPolicyEngine(1024)
	authz, _ = pe.Authorize(ctx, porc)
	assert.True(t, authz)
}

// mockAccessLog implements accesslog.Stream for testing
type mockAccessLog struct {
	records []*events.AccessRecord
	mu      sync.Mutex
}

func (m *mockAccessLog) Send(record *events.AccessRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, record)
	return nil
}

func (m *mockAccessLog) Close() {
	// no-op for testing
}

func (m *mockAccessLog) GetRecords() []*events.AccessRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.records
}

// mockAccessLogFactory implements accesslog.Factory for testing
type mockAccessLogFactory struct {
	stream *mockAccessLog
}

func (m *mockAccessLogFactory) NewStream() (accesslog.Stream, error) {
	return m.stream, nil
}

// mockBackendFactory implements backend.Factory for testing
type mockBackendFactory struct {
	newBackendCalled bool
}

func (m *mockBackendFactory) NewBackend(*opa.Compiler) (backend.Service, error) {
	m.newBackendCalled = true
	return nil, fmt.Errorf("mock backend")
}

// TestWithAccessLog verifies that WithAccessLog option properly configures the access log
func TestWithAccessLog(t *testing.T) {
	mockLog := &mockAccessLog{}
	mockFactory := &mockAccessLogFactory{stream: mockLog}

	opts := &options.EngineOptions{}
	optFunc := options.WithAccessLog(mockFactory)
	optFunc(opts)

	assert.Equal(t, mockFactory, opts.AccessLogFactory)
}

// TestWithBackend verifies that WithBackend option properly configures the backend factory
func TestWithBackend(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../..")
	config.ResetConfig()

	config.VConfig.Set(config.MockEnabled, false)
	defer config.VConfig.Set(config.MockEnabled, true)

	mockFactory := &mockBackendFactory{}

	opts := &options.EngineOptions{}
	optFunc := options.WithBackend(mockFactory)
	optFunc(opts)

	assert.Equal(t, mockFactory, opts.BackendFactory)
}

// TestWithBackendMockModeEnabled verifies that WithBackend ignores the factory when mock mode is enabled
func TestWithBackendMockModeEnabled(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../..")
	config.ResetConfig()

	config.VConfig.Set(config.MockEnabled, true)

	mockFactory := &mockBackendFactory{}

	opts := &options.EngineOptions{}
	optFunc := options.WithBackend(mockFactory)
	optFunc(opts)

	// Backend factory should not be set when mock mode is enabled
	assert.Nil(t, opts.BackendFactory)
}

// TestSetProbeMode verifies that SetProbeMode option properly configures probe mode
func TestSetProbeMode(t *testing.T) {
	tests := []struct {
		name     string
		probe    bool
		expected bool
	}{
		{
			name:     "enable probe mode",
			probe:    true,
			expected: true,
		},
		{
			name:     "disable probe mode",
			probe:    false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &options.AuthzOptions{}
			optFunc := options.SetProbeMode(tt.probe)
			optFunc(opts)

			assert.Equal(t, tt.expected, opts.Probe)
		})
	}
}

// TestEngineOptionsMultipleFuncs verifies that multiple option functions can be applied
func TestEngineOptionsMultipleFuncs(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../..")
	config.ResetConfig()

	config.VConfig.Set(config.MockEnabled, false)
	defer config.VConfig.Set(config.MockEnabled, true)

	mockLog := &mockAccessLog{}
	mockLogFactory := &mockAccessLogFactory{stream: mockLog}
	mockBackendFactory := &mockBackendFactory{}

	opts := &options.EngineOptions{}

	// Apply multiple option functions
	options.WithAccessLog(mockLogFactory)(opts)
	options.WithBackend(mockBackendFactory)(opts)

	assert.Equal(t, mockLogFactory, opts.AccessLogFactory)
	assert.Equal(t, mockBackendFactory, opts.BackendFactory)
}

// TestAuthzOptionsMultipleFuncs verifies that multiple authz option functions can be applied
func TestAuthzOptionsMultipleFuncs(t *testing.T) {
	opts := &options.AuthzOptions{}

	// Apply the option function
	options.SetProbeMode(true)(opts)

	assert.True(t, opts.Probe)

	// Apply it again with different value
	options.SetProbeMode(false)(opts)

	assert.False(t, opts.Probe)
}

// TestWithCompilerOptions verifies that WithCompilerOptions properly configures compiler options
func TestWithCompilerOptions(t *testing.T) {
	// Create mock compiler option functions
	mockCompilerOpt1 := opa.WithRegoVersion(1)
	mockCompilerOpt2 := opa.WithUnsafeBuiltins(opa.Builtins{"http.send": {}})

	opts := &options.EngineOptions{}
	optFunc := options.WithCompilerOptions(mockCompilerOpt1, mockCompilerOpt2)
	optFunc(opts)

	// Verify the compiler options were stored
	compilerOpts := opts.CompilerOptions
	assert.NotNil(t, compilerOpts)
	assert.Equal(t, 2, len(compilerOpts))
}

// TestWithCompilerOptionsSingle verifies that WithCompilerOptions works with a single option
func TestWithCompilerOptionsSingle(t *testing.T) {
	mockCompilerOpt := opa.WithRegoVersion(1)

	opts := &options.EngineOptions{}
	optFunc := options.WithCompilerOptions(mockCompilerOpt)
	optFunc(opts)

	// Verify the compiler option was stored
	compilerOpts := opts.CompilerOptions
	assert.NotNil(t, compilerOpts)
	assert.Equal(t, 1, len(compilerOpts))
}

// TestWithCompilerOptionsEmpty verifies that WithCompilerOptions works with no options
func TestWithCompilerOptionsEmpty(t *testing.T) {
	opts := &options.EngineOptions{}
	optFunc := options.WithCompilerOptions()
	optFunc(opts)

	// Verify the compiler options slice is set (may be nil slice, which is valid in Go)
	compilerOpts := opts.CompilerOptions
	assert.Equal(t, 0, len(compilerOpts))
}

const opasimple = `
package authz
default allow = 1
`
const opahttpsend = `
package authz
default allow = -1

allow = 1 {
    jwt = http.send({"method": "get", "url": "http://%s"})
    jwt != ""
}
`
