//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/auxdata"
	"github.com/urfave/cli/v3"
)

type engine struct {
	domain  string
	pe      core.PolicyEngine
	cmd     *cli.Command
	trace   bool
	stdout  *os.File
	auxdata map[string]interface{}
}

func newEngine(cmd *cli.Command) (*engine, error) {
	// Save original stdout for JSON output
	originalStdout := os.Stdout

	pe, err := common.NewCliPolicyEngine(cmd, originalStdout)
	if err != nil {
		return nil, err
	}

	// Load auxiliary data from CLI flag if provided
	aux, err := auxdata.LoadAuxData(cmd.String("auxdata"))
	if err != nil {
		return nil, err
	}

	return &engine{
		domain:  cmd.String("name"),
		pe:      pe,
		cmd:     cmd,
		trace:   cmd.Root().Bool("trace"),
		stdout:  originalStdout,
		auxdata: aux,
	}, nil
}

func (e *engine) executeMapper(ctx context.Context) (string, error) {
	input := getInputExpression(e.cmd.String("input"))

	be := e.pe.GetBackend()

	mapper, perr := be.GetMapper(ctx, e.domain)
	if perr != nil {
		return "", perr
	}

	var envoyInputData interface{}
	if err := json.Unmarshal([]byte(input), &envoyInputData); err != nil {
		return "", fmt.Errorf("failed to parse Envoy input JSON: %w", err)
	}

	auxdata.MergeAuxData(envoyInputData, e.auxdata)

	porcData, perr := mapper.Evaluate(ctx, envoyInputData)
	if perr != nil {
		return "", fmt.Errorf("failed to evaluate mapper Rego: %w", perr)
	}

	porcJSON, err := json.Marshal(porcData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PORC to JSON: %w", err)
	}

	return string(porcJSON), nil
}

func (e *engine) executeDecision(ctx context.Context, input string) error {
	if e.trace {
		os.Stdout = os.Stderr
	}

	if _, err := e.pe.Authorize(ctx, input); err != nil {
		return err
	}
	return nil
}

func (e *engine) close() {
	if e.trace {
		os.Stdout = e.stdout
	}
}
