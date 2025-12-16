//
//  Copyright © Manetu Inc. All rights reserved.
//

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/manetu/policyengine/cmd/mpe/subcommands/build"
	"github.com/manetu/policyengine/cmd/mpe/subcommands/lint"
	"github.com/manetu/policyengine/cmd/mpe/subcommands/serve"
	"github.com/manetu/policyengine/cmd/mpe/subcommands/test"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/urfave/cli/v3"
)

var logger = logging.GetLogger("mpe")

func main() {
	cmd := &cli.Command{
		Name:  "mpe",
		Usage: "A CLI application for working with the Manetu PolicyEngine",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "trace",
				Aliases: []string{"t"},
				Usage:   "Enable OPA trace logging output to stderr for commands that evaluate REGO",
				Value:   logger.IsTraceEnabled(),
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "test",
				Usage: "Invokes various aspects of policy-decision flow, simplifying policy-domain authoring and verification",
				Commands: []*cli.Command{
					{
						Name:  "decision",
						Usage: "Invokes a policy-decision based on a PORC expression using one or more PolicyDomain bundles",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "test",
								Usage: "The test to decision.  If not specified, the test from the first bundle is used.",
							},
							&cli.StringFlag{
								Name:    "input",
								Aliases: []string{"i"},
								Usage:   "Load input expression from 'FILE', or use '-' for stdin",
							},
							&cli.StringSliceFlag{
								Name:    "bundle",
								Aliases: []string{"b"},
								Usage:   "Load PolicyDomain bundle from `FILE`.  Can be specified multiple times.",
							},
						},
						Action: test.ExecuteDecision,
					},
					{
						Name:  "mapper",
						Usage: "Executes a mapper's Rego code to transform Envoy input into a PORC",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "input",
								Aliases: []string{"i"},
								Usage:   "Load Envoy input from 'FILE', or use '-' for stdin",
							},
							&cli.StringSliceFlag{
								Name:    "bundle",
								Aliases: []string{"b"},
								Usage:   "Load PolicyDomain bundle from `FILE`.  Can be specified multiple times.",
							},
							&cli.StringFlag{
								Name:    "name",
								Aliases: []string{"n"},
								Usage:   "Domain name to use when multiple bundles are provided",
							},
							&cli.StringFlag{
								Name:  "opa-flags",
								Usage: "Additional flags to pass to Rego mapper execution (default: --v0-compatible). Can also be set via MPE_CLI_OPA_FLAGS environment variable.",
							},
							&cli.BoolFlag{
								Name:  "no-opa-flags",
								Usage: "Disable all OPA flags (overrides --opa-flags and MPE_CLI_OPA_FLAGS).",
							},
						},
						Action: test.ExecuteMapper,
					},
					{
						Name:  "envoy",
						Usage: "Executes the full pipeline: Envoy input → mapper Rego → PORC → policy decision",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "input",
								Aliases: []string{"i"},
								Usage:   "Load Envoy input from 'FILE', or use '-' for stdin",
							},
							&cli.StringSliceFlag{
								Name:    "bundle",
								Aliases: []string{"b"},
								Usage:   "Load PolicyDomain bundle from `FILE`.  Can be specified multiple times.",
							},
							&cli.StringFlag{
								Name:    "name",
								Aliases: []string{"n"},
								Usage:   "Domain name to use when multiple bundles are provided",
							},
							&cli.StringFlag{
								Name:  "opa-flags",
								Usage: "Additional flags to pass to Rego mapper execution (default: --v0-compatible). Can also be set via MPE_CLI_OPA_FLAGS environment variable.",
							},
							&cli.BoolFlag{
								Name:  "no-opa-flags",
								Usage: "Disable all OPA flags (overrides --opa-flags and MPE_CLI_OPA_FLAGS).",
							},
						},
						Action: test.ExecuteEnvoy,
					},
				},
			},
			{
				Name:  "serve",
				Usage: "Creates a decision-point service",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "port",
						Usage: "The TCP port to serve on.",
						Value: 9000,
					},
					&cli.StringFlag{
						Name:    "protocol",
						Aliases: []string{"p"},
						Usage:   "The protocol to serve.  Must be one of 'generic' or 'envoy'",
						Value:   "generic",
						Action: func(ctx context.Context, command *cli.Command, s string) error {
							if s != "generic" && s != "envoy" {
								return fmt.Errorf("unsupported protocol: %s", s)
							}
							return nil
						},
					},
					&cli.StringSliceFlag{
						Name:    "bundle",
						Aliases: []string{"b"},
						Usage:   "Load PolicyDomain bundle from `FILE`.  Can be specified multiple times.",
					},
					&cli.StringFlag{
						Name:    "name",
						Aliases: []string{"n"},
						Usage:   "Domain name to use when multiple bundles are provided",
					},
					&cli.StringFlag{
						Name:  "opa-flags",
						Usage: "Additional flags to pass to Rego mapper execution (default: --v0-compatible). Can also be set via MPE_CLI_OPA_FLAGS environment variable.",
					},
					&cli.BoolFlag{
						Name:  "no-opa-flags",
						Usage: "Disable all OPA flags (overrides --opa-flags and MPE_CLI_OPA_FLAGS).",
					},
				},
				Action: serve.Execute,
			},
			{
				Name:  "lint",
				Usage: "Validate PolicyDomain YAML files for syntax errors and lint embedded Rego code",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "PolicyDomain YAML file to lint (.yml, .yaml). Validates YAML syntax and lints all embedded Rego code with cross-references resolved. Can be specified multiple times.",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "opa-flags",
						Usage: "Additional flags to pass to 'opa check' command (default: --v0-compatible). Can also be set via MPE_CLI_OPA_FLAGS environment variable.",
					},
					&cli.BoolFlag{
						Name:  "no-opa-flags",
						Usage: "Disable all OPA flags (overrides --opa-flags and MPE_CLI_OPA_FLAGS).",
					},
				},
				Action: lint.Execute,
			},
			{
				Name:  "build",
				Usage: "Build PolicyDomain YAML from PolicyDomainReference (with external .rego files)",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "PolicyDomainReference YAML file to build (.yml, .yaml). Can be specified multiple times.",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file path (only valid when building a single file). If not specified, generates '<input>-built.yml'",
					},
				},
				Action: build.Execute,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
