//
//  Copyright © Manetu Inc. All rights reserved.
//

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

// Server represents a generic decision point server that serves the REST API.
type Server struct {
	echo *echo.Echo
}

// CreateServer creates and starts a new generic decision point server.
// It sets up the REST API endpoints, Swagger UI, and OpenAPI schema.
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

// Stop gracefully stops the Server by shutting down the Echo HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}
