//
//  Copyright © Manetu Inc. All rights reserved.
//

package serve

import (
	"context"
	"os"
	"os/signal"

	"github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/decisionpoint"
	"github.com/manetu/policyengine/pkg/decisionpoint/envoy"
	"github.com/manetu/policyengine/pkg/decisionpoint/generic"
	"github.com/urfave/cli/v3"
)

var logger = logging.GetLogger("policyengine")

const agent string = "serve"

// Execute runs the serve command, starting a decision point server based on the configured protocol.
// It supports both "generic" and "envoy" protocols and gracefully shuts down on interrupt signals.
func Execute(ctx context.Context, cmd *cli.Command) error {
	port := cmd.Int("port")

	pe, err := common.NewCliPolicyEngine(cmd, os.Stdout)
	if err != nil {
		return err
	}

	var server decisionpoint.Server
	switch cmd.String("protocol") {
	case "generic":
		server, err = generic.CreateServer(pe, port)
	case "envoy":
		server, err = envoy.CreateServer(pe, port, cmd.String("name"))
	}
	if err != nil {
		return err
	}

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info(agent, "shutdown", "Shutting down server...")

	err = server.Stop(ctx)
	if err != nil {
		return err
	}

	logger.Info(agent, "shutdown", "Server exited gracefully.")
	return nil
}
