//
//  Copyright © Manetu Inc. All rights reserved.
//

package model

import (
	"context"

	"github.com/manetu/policyengine/pkg/common"
)

// Evaluate evaluates the mapper policy against the provided input.
func (p *Mapper) Evaluate(ctx context.Context, input interface{}) (interface{}, *common.PolicyError) {
	result, err := p.Ast.Evaluate(ctx, "porc = data.mapper.porc", input)
	if err != nil {
		return nil, err
	}

	return result.Bindings["porc"], nil
}
