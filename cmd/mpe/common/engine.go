package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/backend/local"
	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/urfave/cli/v3"
)

// GetRegoVersionFromOPAFlags determines the Rego version from OPA flags.
// It checks CLI flags and environment variables to determine whether to use
// Rego v0 or v1.
func GetRegoVersionFromOPAFlags(noOPAFlags bool, opaFlagsStr string) ast.RegoVersion {
	if noOPAFlags {
		// Explicitly disable OPA flags - use default OPA version (v1)
		return ast.RegoV1
	}

	opaFlags := opaFlagsStr
	if opaFlags == "" {
		// Check environment variable
		opaFlags = os.Getenv("MPE_CLI_OPA_FLAGS")
		if opaFlags == "" {
			// Use default
			opaFlags = "--v0-compatible"
		}
	}

	// Parse the OPA flags string
	opaFlags = strings.ToLower(strings.TrimSpace(opaFlags))
	if strings.Contains(opaFlags, "--v0-compatible") {
		return ast.RegoV0
	}

	// Default to v0 if unrecognized
	log.Printf("WARNING: Unrecognized OPA flags '%s', defaulting to v0", opaFlagsStr)
	return ast.RegoV0
}

// NewCliPolicyEngine creates a new PolicyEngine instance configured from CLI command flags.
// It sets up the registry, access logging, backend, and compiler options based on the provided command.
func NewCliPolicyEngine(cmd *cli.Command, stdout io.Writer) (core.PolicyEngine, error) {
	// Enable trace logging if requested (global flag from root command)
	traceEnabled := cmd.Root().Bool("trace")

	bundles := cmd.StringSlice("bundle")
	if len(bundles) == 0 {
		return nil, fmt.Errorf("at least one bundle must be specified")
	}

	// Auto-build any PolicyDomainReference files
	bundles, err := AutoBuildReferenceFiles(bundles)
	if err != nil {
		return nil, err
	}

	r, err := registry.NewRegistry(bundles)
	if err != nil {
		return nil, err
	}

	// Get Rego version from OPA flags (CLI flags and environment variables)
	noOPAFlags := cmd.Bool("no-opa-flags")
	opaFlags := cmd.String("opa-flags")
	regoVersion := GetRegoVersionFromOPAFlags(noOPAFlags, opaFlags)

	return core.NewPolicyEngine(
		options.WithAccessLog(accesslog.NewIoWriterFactory(stdout)),
		options.WithBackend(local.NewFactory(r)),
		options.WithCompilerOptions(
			opa.WithRegoVersion(regoVersion),
			opa.WithDefaultTracing(traceEnabled)))
}
