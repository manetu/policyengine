//
//  Copyright © Manetu Inc. All rights reserved.
//

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

// EvaluateBool evaluates a query against the policy AST, returning a boolean result suitable for all phases besides phase1
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

// EvaluateInt evaluates a query against the policy AST, returning an integer result suitable for phase1
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
