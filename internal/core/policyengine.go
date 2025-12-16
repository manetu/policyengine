//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/core/types"
	"github.com/mohae/deepcopy"
	"google.golang.org/protobuf/types/known/timestamppb"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

const (
	auditNotPhase1 = math.MaxInt
)

// PolicyEngine is an object holding data for optimization
type PolicyEngine struct {
	audit    accesslog.Stream
	backend  backend.Service
	compiler *opa.Compiler

	includeAllBundles bool
}

var logger = logging.GetLogger("policyengine")

const (
	agent     string = "policyengine"
	resource  string = "resource"
	operation string = "operation"
	principal string = "principal"

	// Sub ...
	Sub string = "sub"
	// Mrealm ...
	Mrealm string = "mrealm"
	// Mroles ...
	Mroles string = "mroles"
	// Scopes ...
	Scopes string = "scopes"
	// Mgroups ...
	Mgroups string = "mgroups"
	// Mannotations ...
	Mannotations string = "mannotations"
)

// NewPolicyEngine returns an PE instance.
func NewPolicyEngine(engineOptions *options.EngineOptions) (*PolicyEngine, error) {

	engineOptions.CompilerOptions = append(engineOptions.CompilerOptions, opa.WithUnsafeBuiltins(getUnsafeBuiltins()))
	compiler := opa.NewCompiler(engineOptions.CompilerOptions...)

	al, err := engineOptions.AccessLogFactory.NewStream()
	if err != nil {
		return nil, err
	}

	be, err := engineOptions.BackendFactory.NewBackend(compiler)
	if err != nil {
		return nil, err
	}

	return &PolicyEngine{
		audit:             al,
		backend:           be,
		compiler:          compiler,
		includeAllBundles: config.VConfig.GetBool(config.IncludeAllBundles), // default is to debug all bundles
	}, nil
}

func (pe *PolicyEngine) setOverrideReason(record *events.AccessRecord, result int) string {
	auditReason := ""
	if result == auditNotPhase1 { // ie, is not phase1
		record.SystemOverride = false
		return auditReason
	}

	if result == 0 {
		// should not ever see this
		logger.Warn(agent, "setOverrideReason", "phase1 result cannot be zero")
	}

	record.SystemOverride = true

	if result < 0 {
		result = -result

		var r events.AccessRecord_BypassDenyReason

		//should always map, just being defensive
		// #nosec G115
		if events.AccessRecord_BypassDenyReason_name[int32(result)] != "" {
			// #nosec G115
			r = events.AccessRecord_BypassDenyReason(int32(result))
			auditReason = r.String()
		} else {
			r = events.AccessRecord_NOT_DENIED
		}
		record.OverrideReason = &events.AccessRecord_DenyReason{DenyReason: r}
	} else {
		var r events.AccessRecord_BypassGrantReason

		//should always map, just being defensive
		// #nosec G115
		if events.AccessRecord_BypassGrantReason_name[int32(result)] != "" {
			// #nosec G115
			r = events.AccessRecord_BypassGrantReason(int32(result))
			auditReason = r.String()
		} else {
			r = events.AccessRecord_NOT_GRANTED
		}
		record.OverrideReason = &events.AccessRecord_GrantReason{GrantReason: r}
	}

	return auditReason
}

func (pe *PolicyEngine) auditDecision(aos *options.AuthzOptions, record *events.AccessRecord, resource string, reason string, porc map[string]interface{}, logonly bool, result int) {
	auditReason := pe.setOverrideReason(record, result)

	if logger.IsDebugEnabled() {
		if result != auditNotPhase1 {
			logger.Debugf(agent, "auditDecision", "resource: %s, reason: %s, options: %+v, result: %s", resource, reason, aos, auditReason)
		} else {
			logger.Debugf(agent, "auditDecision", "resource: %s, reason: %s, options: %+v", resource, reason, aos)
		}
		logger.Debug(agent, "auditDecision", "access record:")
		common.PrettyPrint(record)
		logger.Debug(agent, "auditDecision", "porc used:")
		common.PrettyPrint(porc)
	}

	if pe.audit != nil && !aos.Probe && !logonly {
		err := pe.audit.Send(record)
		if err != nil {
			logger.Errorf(agent, "auditDecision", "unable to send message for accesslog %+v", err)
		}
	}
}

func (pe *PolicyEngine) appendReferences(ar *events.AccessRecord, phases ...*phase) {
	for _, p := range phases {
		ar.References = append(ar.References, p.bundles...)
	}
}

// fetchAnnotations... caller input principalMap is validated and could report error which will abort the authorization
func (pe *PolicyEngine) fetchAnnotations(ctx context.Context, principalMap map[string]interface{}) map[string]interface{} {
	toArrFn := func(tag string) []string {
		arr := []string{}
		if gs, ok := principalMap[tag].([]interface{}); ok {
			for _, x := range gs {
				if g, okk := x.(string); okk {
					arr = append(arr, g)
				}
			}
		}

		return arr
	}

	groups := toArrFn(Mgroups)
	roles := toArrFn(Mroles)
	scopes := toArrFn(Scopes)

	var (
		annots map[string]interface{}
	)
	if a, ok := principalMap[Mannotations].(map[string]interface{}); ok {
		annots = deepcopy.Copy(a).(map[string]interface{})
	} else if principalMap[Mannotations] != nil {
		logger.Debugf(agent, "fetchAnnotations", "invalid annotation %+v", principalMap[Mannotations])
	}

	return pe.GetAnnotations(ctx, annots, scopes, groups, roles)
}

func (pe *PolicyEngine) resolveResource(ctx context.Context, mrn string) (*model.Resource, *common.PolicyError) {
	logger.Debugf(agent, "resolveResource", "mrn: %s", mrn)
	res, err := pe.backend.GetResource(ctx, mrn)
	if err != nil {
		logger.Debugf(agent, "resolveResource", "error getting resource: %+v", err)
		return nil, err
	}
	rg, err := pe.backend.GetResourceGroup(ctx, res.Group)
	if err != nil {
		logger.Debugf(agent, "resolveResource", "error getting resource group: %+v", err)
		return nil, err
	}

	resCopy := deepcopy.Copy(res).(*model.Resource)
	resCopy.Annotations = mergeAnnotations(rg.Annotations, resCopy.Annotations)
	return resCopy, nil
}

// Authorize is the main function that calls opa
func (pe *PolicyEngine) Authorize(ctx context.Context, input types.PORC, authOptions *options.AuthzOptions) bool {
	logger.Debug(agent, "authorize", "Enter")
	defer logger.Debug(agent, "authorize", "Exit")

	//principal is expected in the input (and not from phase1 policy processor)
	principalMap := map[string]interface{}{}
	if p, pok := input[principal]; pok && p != nil {
		if pm, _ := p.(map[string]interface{}); pm != nil {
			principalMap = pm
		}
	}

	if len(principalMap) == 0 {
		//do not add annotations if there was no principalMap (no JWT)
		logger.Debugf(agent, "authorize", "annotations not obtained: ...not adding to empty principal")
	} else {
		principalMap[Mannotations] = pe.fetchAnnotations(ctx, principalMap)
		logger.Debugf(agent, "authorize", "annotations obtained: %+v", principalMap[Mannotations])
	}

	var (
		resMrn string
		resErr *common.PolicyError // this is used only post phase1
	)

	switch input[resource].(type) {
	case string:
		resMrn = input[resource].(string)
		logger.Tracef(agent, "authorize", "calling getResource, mrn: %s", resMrn)
		input[resource], resErr = pe.resolveResource(ctx, resMrn)
		if resErr != nil {
			logger.Debugf(agent, "authorize", "[phase3] error getting resource: %+v", resErr)
			input[resource] = &model.Resource{ID: resMrn}
		} else {
			logger.Debugf(agent, "authorize", "input resource updated: %+v", input[resource])
		}
	default:
		r, _ := input[resource].(map[string]interface{})
		resMrn, _ = r["id"].(string)
		owner, _ := r["owner"].(string)
		group, _ := r["group"].(string)
		//note that these annotations are from porc which is a JSON struct
		//annotations here does not have to be embedded into strings as those
		//in protobufs
		annots, _ := r["annotations"].(map[string]interface{})
		if annots == nil {
			annots = map[string]interface{}{}
		}
		classification, _ := r["classification"].(string)

		input[resource] = &model.Resource{
			ID:             resMrn,
			Owner:          owner,
			Group:          group,
			Annotations:    annots,
			Classification: classification,
		}
	}

	op, _ := input[operation].(string)

	ar := &events.AccessRecord{
		Principal:  &events.AccessRecord_Principal{},
		Operation:  op,
		Resource:   resMrn,
		References: []*events.AccessRecord_BundleReference{},
		Metadata: &events.AccessRecord_Metadata{
			Timestamp: timestamppb.New(time.Now()),
			Id:        uuid.New().String(),
		},
	}

	ar.Principal.Subject, _ = principalMap[Sub].(string)
	ar.Principal.Realm, _ = principalMap[Mrealm].(string)

	if logger.IsDebugEnabled() {
		logger.Debugf(agent, "authorize", "principalMap: %+v", principalMap)
		logger.Debugf(agent, "authorize", "got access record: %+v", ar)
	}

	auditDecision := struct {
		phase1Result int //must be auditNotPhase1 if decision is not from phase 1
		reason       string
	}{}

	// -------------------------- NOTE: all returns audited -----------------
	defer func() {
		pe.auditDecision(authOptions, ar, resMrn, auditDecision.reason, input, false, auditDecision.phase1Result)
	}()

	realizedPorc, err := json.Marshal(input)
	if err != nil {
		logger.Errorf(agent, "authorize", "failed to marshal fully realized PORC:\n, %+v", input)

		perr := &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_INVALPARAM_ERROR, Reason: err.Error()}

		ar.References = append(ar.References, buildBundleReference(perr, nil, events.AccessRecord_BundleReference_RESOURCE, resMrn, events.AccessRecord_DENY))
		ar.Decision = events.AccessRecord_DENY

		auditDecision.reason = "failed to marshal PORC"
		auditDecision.phase1Result = auditNotPhase1

		return false
	}

	ar.Porc = string(realizedPorc)

	var (
		phasesWg sync.WaitGroup
	)

	phasesWg.Add(4) //4 phases

	var (
		phase1Result events.AccessRecord_Decision
	)
	p1 := &phase1{}
	go func() {
		defer phasesWg.Done()
		phase1Result = p1.exec(ctx, pe, input, op)
	}()

	var (
		phase2Result bool
	)
	p2 := &phase2{}
	go func() {
		defer phasesWg.Done()
		phase2Result = p2.exec(ctx, pe, principalMap, input)
	}()

	var (
		phase3Result bool
	)
	p3 := &phase3{}
	go func() {
		defer phasesWg.Done()
		// Resource resolution failure will cause evaluation to terminate post phase 1
		// and will add the required DENY bundle (which is needed for audit).
		// The result itself would be DENY and phase 3 won't be evaluated. No need to execute
		if resErr == nil {
			// either resource group is provided in input or the MRN was resolved successfully.
			phase3Result = p3.exec(ctx, pe, input)
		}
	}()

	var (
		phase4Result bool
	)
	p4 := &phase4{}
	go func() {
		defer phasesWg.Done()
		phase4Result = p4.exec(ctx, pe, principalMap, input)
	}()

	phasesWg.Wait()

	logger.Debug(agent, "authorize", "phases completed...begin evaulation")

	// include execution records for audit and display purposes
	if pe.includeAllBundles {
		pe.appendReferences(ar, &p1.phase, &p2.phase, &p3.phase, &p4.phase)
	} else {
		pe.appendReferences(ar, &p1.phase)
	}

	// start with phase1Result ... potentially events.AccessRecord_UNSPECIFIED
	ar.Decision = phase1Result

	// Phase 1 result AccessRecord_DENY or AccessRecord_GRANT will be final (other phases are not considered).
	// Phase 1 result AccessRecord_UNSPECIFIED hands decision to other phases.

	switch phase1Result {
	case events.AccessRecord_GRANT:
		auditDecision.phase1Result = p1.result
		auditDecision.reason = "authorized in phase1"

		return true
	case events.AccessRecord_DENY:
		auditDecision.phase1Result = p1.result
		auditDecision.reason = "denied in phase1"

		return false
	}

	// ----------- proceed to POST phase1 evaulation processing ----------

	// defaults
	auditDecision.phase1Result = auditNotPhase1
	ar.Decision = events.AccessRecord_DENY

	if resErr != nil {
		logger.Tracef(agent, "authorize", "resource error (err-%s). Stopping evaluation post phase1", resErr)

		auditDecision.reason = "error getting resource"

		ar.References = append(ar.References, buildBundleReference(resErr, nil, events.AccessRecord_BundleReference_RESOURCE, resMrn, events.AccessRecord_DENY))

		return false
	}

	if !pe.includeAllBundles {
		pe.appendReferences(ar, &p2.phase)
	}
	if !phase2Result {
		return false
	}

	if !pe.includeAllBundles {
		pe.appendReferences(ar, &p3.phase)
	}
	if !phase3Result {
		return false
	}

	if !pe.includeAllBundles {
		pe.appendReferences(ar, &p4.phase)
	}
	if !phase4Result {
		return false
	}

	//everything passed
	ar.Decision = events.AccessRecord_GRANT

	logger.Debugf(agent, "authorize", "authorized principal: %+v", principalMap)

	return true
}

// GetBackend returns the backend service used by this policy engine.
func (pe *PolicyEngine) GetBackend() backend.Service {
	return pe.backend
}

// IsAllBundles returns whether the policy engine is configured to include all bundles (needed for debugging).
func (pe *PolicyEngine) IsAllBundles() bool {
	return pe.includeAllBundles
}
