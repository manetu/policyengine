//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package decisionpoint provides interfaces and implementations for
// Policy Decision Point (PDP) servers.
//
// A PDP server exposes the policy engine as a network service that
// Policy Enforcement Points (PEPs) can call to make authorization
// decisions.
//
// # Available Implementations
//
// The following PDP server implementations are available:
//   - [generic]: HTTP/REST server with OpenAPI documentation
//   - [envoy]: External authorization server for Envoy proxy
//
// # Usage
//
// Create and start a decision point server:
//
//	pe, _ := core.NewPolicyEngine(options.WithBackend(backend))
//	server, _ := generic.CreateServer(pe, 8080)
//	defer server.Stop(ctx)
package decisionpoint

import "context"

// Server is the interface for PDP servers that can be gracefully stopped.
//
// Implementations must ensure that [Stop] completes any in-flight requests
// before returning.
type Server interface {
	// Stop gracefully shuts down the server, waiting for active requests
	// to complete or until the context is cancelled.
	Stop(context.Context) error
}
