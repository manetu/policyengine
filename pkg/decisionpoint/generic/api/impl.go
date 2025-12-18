//
//  Copyright © Manetu Inc. All rights reserved.
//

package api

import (
	"context"
	"encoding/json"

	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/options"
)

// Server implements the generic decision point API server.
type Server struct {
	pe core.PolicyEngine
}

// NewServer creates a new API server instance with the given PolicyEngine.
func NewServer(pe core.PolicyEngine) Server {
	return Server{
		pe: pe,
	}
}

// Decision handles decision requests by evaluating the policy engine with the provided request body.
func (s Server) Decision(ctx context.Context, request DecisionRequestObject) (DecisionResponseObject, error) {
	porc, err := json.Marshal(request.Body)
	if err != nil {
		return nil, err
	}

	probe := request.Params.Probe != nil && *request.Params.Probe
	allow, _ := s.pe.Authorize(ctx, string(porc), options.SetProbeMode(probe))
	return Decision200JSONResponse{
		Allow: &allow,
	}, nil
}
