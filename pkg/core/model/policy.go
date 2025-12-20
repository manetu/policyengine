//
//  Copyright © Manetu Inc. All rights reserved.
//

// This file contains policy evaluation methods for the model package.

package model

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manetu/policyengine/pkg/common"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

func (p *Policy) evaluate(ctx context.Context, input interface{}) (interface{}, *common.PolicyError) {
	result, err := p.Ast.Evaluate(ctx, "x = data.authz.allow", input)
	if err != nil {
		return nil, err
	}

	return result.Bindings["x"], nil
}

// EvaluateBool evaluates the policy and returns a boolean authorization decision.
//
// This method executes the "data.authz.allow" query against the policy AST
// with the provided input. It's used for the identity phase (phase 2),
// resource phase (phase 3), and scope phase (phase 4) which use boolean
// GRANT/DENY decisions.
//
// The input should be a map containing the PORC data available to the policy:
// principal, operation, resource, and context.
//
// Returns false with a [common.PolicyError] if evaluation fails or produces
// a non-boolean result.
func (p *Policy) EvaluateBool(ctx context.Context, input interface{}) (bool, *common.PolicyError) {
	x, err := p.evaluate(ctx, input)
	if err != nil {
		return false, err
	}

	var (
		b  bool
		ok bool
	)

	if b, ok = x.(bool); !ok { // bad results
		return false, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_UNKNOWN_ERROR, Reason: fmt.Sprintf("unexpected evaluation result: %+v", x)}
	}

	return b, nil
}

// EvaluateInt evaluates the policy and returns a tri-level integer result.
//
// This method is used for the operation phase (phase 1) of the authorization
// pipeline, which uses tri-level output instead of boolean:
//
//   - Negative (e.g., -1): DENY - same as any phase denying
//   - Zero (0): GRANT - continue evaluating other phases
//   - Positive (e.g., 1): GRANT Override - immediately grant, skip all other phases
//
// The magnitude can serve as a reason code for auditing (e.g., -1 vs -2 for
// different denial reasons). The sign determines the authorization behavior.
//
// Returns -1 with a [common.PolicyError] if evaluation fails or produces
// a non-numeric result.
func (p *Policy) EvaluateInt(ctx context.Context, input interface{}) (int, *common.PolicyError) {
	x, perr := p.evaluate(ctx, input)
	if perr != nil {
		return -1, perr
	}

	var (
		l   int64
		err error
	)

	if n, ok := x.(json.Number); !ok { // bad results
		return -1, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_UNKNOWN_ERROR, Reason: fmt.Sprintf("unexpected evaluation result: %+v", x)}
	} else if l, err = n.Int64(); err != nil {
		return -1, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_UNKNOWN_ERROR, Reason: fmt.Sprintf("cannot extract integer result: %s", err)}
	}
	return int(l), nil
}
