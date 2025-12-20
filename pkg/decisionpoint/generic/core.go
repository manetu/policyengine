//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package generic provides an HTTP/REST server for the policy engine.
//
// The generic decision point exposes the policy engine via a REST API
// with OpenAPI documentation. It's suitable for applications that need
// a standard HTTP interface for authorization decisions.
//
// # Features
//
//   - REST API for authorization requests
//   - Swagger UI at /swagger-ui/
//   - OpenAPI specification at /openapi.yaml
//
// # Usage
//
//	pe, _ := core.NewPolicyEngine(options.WithBackend(backend))
//	server, err := generic.CreateServer(pe, 8080)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer server.Stop(ctx)
package generic

import (
	"context"
	"embed"
	"fmt"
	"net/http"

	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/decisionpoint"
	"github.com/manetu/policyengine/pkg/decisionpoint/generic/api"

	"github.com/labstack/echo/v4"
)

//go:embed swagger-ui/*
var swaggerUI embed.FS

//go:embed openapi.yaml
var schema embed.FS

// Server is the HTTP server for the generic decision point.
//
// Server wraps an Echo HTTP server configured with the authorization API,
// Swagger UI, and OpenAPI schema endpoints.
type Server struct {
	echo *echo.Echo
}

// CreateServer creates and starts a generic decision point HTTP server.
//
// The server starts immediately in a background goroutine and listens on
// the specified port. It provides the following endpoints:
//   - POST /authorize: Authorization decision endpoint
//   - GET /swagger-ui/*: Swagger UI for API exploration
//   - GET /openapi.yaml: OpenAPI specification
//
// Returns a [decisionpoint.Server] that can be used to stop the server.
// Use [Server.Stop] to gracefully shut down when done.
func CreateServer(pe core.PolicyEngine, port int) (decisionpoint.Server, error) {
	e := echo.New()
	apiServer := api.NewServer(pe)

	api.RegisterHandlers(e, api.NewStrictHandler(
		apiServer,
		// add middlewares here if needed
		[]api.StrictMiddlewareFunc{},
	))

	e.GET("/swagger-ui/*", echo.WrapHandler(http.FileServer(http.FS(swaggerUI))))
	e.GET("/openapi.yaml", echo.WrapHandler(http.FileServer(http.FS(schema))))

	// Start server in goroutine since e.Start() blocks
	go func() {
		if err := e.Start(fmt.Sprintf(":%d", port)); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal(err)
		}
	}()

	return &Server{
		echo: e,
	}, nil
}

// Stop gracefully shuts down the HTTP server.
//
// Stop waits for active requests to complete before returning, or until
// the context is cancelled. After Stop returns, the server will no longer
// accept new connections.
func (s *Server) Stop(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}
