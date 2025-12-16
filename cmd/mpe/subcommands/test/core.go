//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// ExecuteMapper executes a stand-alone mapper operation and prints the output
func ExecuteMapper(ctx context.Context, cmd *cli.Command) error {
	engine, err := newEngine(cmd)
	if err != nil {
		return err
	}
	defer engine.close()

	output, err := engine.executeMapper(ctx)
	if err != nil {
		return err
	}

	fmt.Println(output)
	return nil
}

// ExecuteDecision executes a stand-alone policy decision and prints the output
func ExecuteDecision(ctx context.Context, cmd *cli.Command) error {
	engine, err := newEngine(cmd)
	if err != nil {
		return err
	}
	defer engine.close()

	return engine.executeDecision(ctx, getInputExpression(cmd.String("input")))
}

// ExecuteEnvoy executes an end-to-end mapper + decision pipeline and prints the output
func ExecuteEnvoy(ctx context.Context, cmd *cli.Command) error {
	engine, err := newEngine(cmd)
	if err != nil {
		return err
	}
	defer engine.close()

	porc, err := engine.executeMapper(ctx)
	if err != nil {
		return err
	}

	return engine.executeDecision(ctx, porc)
}
