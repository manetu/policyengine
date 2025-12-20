//
//  Copyright © Manetu Inc. All rights reserved.
//

// This file contains mapper evaluation methods for the model package.

package model

import (
	"context"

	"github.com/manetu/policyengine/pkg/common"
)

// Evaluate transforms non-PORC input into a PORC structure.
//
// The mapper policy's data.mapper.porc rule is executed with the provided
// input. Mappers are typically used with external systems like Envoy that
// have fixed request formats.
//
// Example input (Envoy ext_authz format):
//
//	{
//	    "request": {
//	        "http": {
//	            "method": "GET",
//	            "path": "/api/users/123",
//	            "headers": {"authorization": "Bearer ..."}
//	        }
//	    },
//	    "destination": {"principal": "spiffe://cluster/ns/default/sa/api"}
//	}
//
// The mapper policy transforms this into a PORC structure with principal,
// operation, resource, and context fields.
//
// Returns the PORC as interface{} (typically map[string]interface{}),
// or a [common.PolicyError] if evaluation fails.
func (p *Mapper) Evaluate(ctx context.Context, input interface{}) (interface{}, *common.PolicyError) {
	result, err := p.Ast.Evaluate(ctx, "porc = data.mapper.porc", input)
	if err != nil {
		return nil, err
	}

	return result.Bindings["porc"], nil
}
