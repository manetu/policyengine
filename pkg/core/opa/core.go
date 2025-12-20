//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package opa provides abstractions for compiling and evaluating Open Policy Agent
// (OPA) Rego policies.
//
// This package wraps the OPA library to provide a simplified API for the policy
// engine. It handles policy compilation, AST management, and query evaluation.
//
// # Compiler
//
// The [Compiler] compiles Rego source code into executable [Ast] objects:
//
//	compiler := opa.NewCompiler(
//	    opa.WithRegoVersion(ast.RegoV1),
//	    opa.WithUnsafeBuiltins(opa.Builtins{"http.send": {}}),
//	)
//
//	ast, err := compiler.Compile("policy-name", opa.Modules{
//	    "policy.rego": policySource,
//	})
//
// # AST Evaluation
//
// The compiled [Ast] can be evaluated with input data:
//
//	result, err := ast.Evaluate(ctx, "x = data.authz.allow", input)
//	if result.Bindings["x"].(bool) {
//	    // Access allowed
//	}
//
// # Compiler Options
//
// Various options control compilation behavior:
//   - [WithRegoVersion]: Set Rego language version (V0 or V1)
//   - [WithCapabilities]: Configure OPA capabilities
//   - [WithUnsafeBuiltins]: Disable specific built-in functions
//   - [WithDefaultTracing]: Enable evaluation tracing
package opa

import (
	"context"
	"fmt"
	"strings"

	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/common"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/mohae/deepcopy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

var logger = logging.GetLogger("opa")
var agent = "opa"

// Builtins is a set of Rego built-in function names.
//
// Used with [WithUnsafeBuiltins] to specify which built-in functions should
// be disabled in the compiler for security purposes:
//
//	unsafe := opa.Builtins{"http.send": {}, "opa.runtime": {}}
//	compiler := opa.NewCompiler(opa.WithUnsafeBuiltins(unsafe))
type Builtins map[string]struct{}

// Compiler compiles Rego source code into executable AST objects.
//
// Compiler handles the parsing and compilation of Rego policies with
// configurable options for language version and capabilities. A single
// Compiler instance can compile multiple policies.
//
// Create a Compiler with [NewCompiler] and compile policies with [Compile]:
//
//	compiler := opa.NewCompiler(opa.WithRegoVersion(ast.RegoV1))
//	ast, err := compiler.Compile("my-policy", opa.Modules{
//	    "policy.rego": `package authz
//	        default allow = false
//	        allow { input.principal.sub != "" }`,
//	})
type Compiler struct {
	options *CompilerOptions
}

// Ast represents a compiled Rego policy ready for evaluation.
//
// Ast contains the compiled OPA abstract syntax tree along with
// configuration for evaluation (such as tracing). Use [Evaluate]
// to execute queries against the compiled policy.
type Ast struct {
	name     string
	compiler *ast.Compiler
	trace    bool
}

// Modules maps module names to their Rego source code.
//
// When compiling a policy with dependencies, include all required
// modules in the map:
//
//	modules := opa.Modules{
//	    "policy.rego": mainPolicySource,
//	    "helpers.rego": helperLibrarySource,
//	}
type Modules map[string]string

// CompilerOptions holds configuration for the Rego compiler.
//
// Use functional options like [WithRegoVersion] and [WithCapabilities]
// when calling [NewCompiler] rather than creating this struct directly.
type CompilerOptions struct {
	regoVersion  ast.RegoVersion
	capabilities *ast.Capabilities
	trace        bool
}

func filter[T any](ss []T, test func(T) bool) (ret []T) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}

// CompilerOptionFunc is a functional option for configuring [Compiler] instances.
//
// Pass these functions to [NewCompiler] to customize the compiler's behavior.
type CompilerOptionFunc func(*CompilerOptions)

// WithRegoVersion sets the Rego language version for the compiler.
//
// Supported versions:
//   - ast.RegoV0: Original Rego syntax (default)
//   - ast.RegoV1: Rego v1 with stricter syntax
func WithRegoVersion(regoVersion ast.RegoVersion) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.regoVersion = regoVersion
	}
}

// WithCapabilities sets the OPA capabilities for the compiler.
//
// Capabilities define which Rego features and built-in functions are available.
// When using both WithCapabilities and [WithUnsafeBuiltins], call WithCapabilities
// first as WithUnsafeBuiltins modifies the capabilities.
func WithCapabilities(capabilities *ast.Capabilities) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.capabilities = capabilities
	}
}

// WithDefaultCapabilities resets capabilities to the OPA defaults for this version.
//
// Use this to restore full capabilities after they've been modified, such as
// when creating a mapper compiler that needs built-ins disabled for policies.
func WithDefaultCapabilities() CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.capabilities = ast.CapabilitiesForThisVersion()
	}
}

// WithUnsafeBuiltins removes specified built-in functions from OPA capabilities.
//
// This is a security feature to prevent policies from using potentially
// dangerous functions like http.send that could exfiltrate data or cause
// side effects. Must be called after [WithCapabilities] if both are used.
//
// Example:
//
//	compiler := opa.NewCompiler(
//	    opa.WithUnsafeBuiltins(opa.Builtins{"http.send": {}, "opa.runtime": {}}),
//	)
func WithUnsafeBuiltins(unsafeBuiltins Builtins) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		// see: https://github.com/open-policy-agent/opa/security/advisories/GHSA-f524-rf33-2jjr
		o.capabilities.Builtins = filter(o.capabilities.Builtins, func(builtin *ast.Builtin) bool { _, ok := unsafeBuiltins[builtin.Name]; return !ok })
	}
}

// WithDefaultTracing enables or disables trace output during policy evaluation.
//
// When tracing is enabled, detailed evaluation steps are printed to stdout
// during [Ast.Evaluate] calls. This is useful for debugging policy logic.
// Individual evaluations can override this default using [WithTrace].
//
// Defaults to the current log tracing level.
func WithDefaultTracing(trace bool) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.trace = trace
	}
}

// NewCompiler creates a new [Compiler] with the specified options.
//
// Default configuration:
//   - Rego version: V0
//   - Capabilities: Full OPA capabilities for this version
//   - Tracing: Based on log level
//
// Example:
//
//	compiler := opa.NewCompiler(
//	    opa.WithRegoVersion(ast.RegoV1),
//	    opa.WithUnsafeBuiltins(opa.Builtins{"http.send": {}}),
//	)
func NewCompiler(options ...CompilerOptionFunc) *Compiler {
	opts := &CompilerOptions{
		regoVersion:  ast.RegoV0,
		capabilities: ast.CapabilitiesForThisVersion(),
		trace:        logger.IsTraceEnabled(),
	}
	for _, o := range options {
		o(opts)
	}

	return &Compiler{options: opts}
}

// Clone creates a new [Compiler] based on the current configuration.
//
// The cloned compiler inherits all options from the source but can be
// modified independently via the provided options. This is useful for
// creating variant compilers, such as one for policies with restricted
// capabilities and another for mappers with full capabilities.
func (c *Compiler) Clone(options ...CompilerOptionFunc) *Compiler {
	opts := &CompilerOptions{
		regoVersion:  c.options.regoVersion,
		capabilities: deepcopy.Copy(c.options.capabilities).(*ast.Capabilities),
		trace:        c.options.trace,
	}
	for _, o := range options {
		o(opts)
	}

	return &Compiler{options: opts}
}

// Compile parses and compiles Rego modules into an executable [Ast].
//
// The name parameter identifies the policy for logging and debugging.
// The modules map contains all Rego source files needed for compilation,
// including the main policy and any dependencies.
//
// Returns an error if any module fails to parse or if compilation fails
// (e.g., due to undefined references or type errors).
func (c *Compiler) Compile(name string, modules Modules) (*Ast, error) {
	parsed := make(map[string]*ast.Module, len(modules))

	for f, module := range modules {
		var pm *ast.Module
		var err error
		if pm, err = ast.ParseModuleWithOpts(f, module, ast.ParserOptions{RegoVersion: c.options.regoVersion}); err != nil {
			return nil, err
		}
		parsed[f] = pm
	}

	compiler := ast.NewCompiler().WithCapabilities(c.options.capabilities)

	compiler.Compile(parsed)

	if compiler.Failed() {
		return nil, compiler.Errors
	}

	return &Ast{
		name:     name,
		compiler: compiler,
		trace:    c.options.trace,
	}, nil
}

// EvalOptions holds configuration for individual policy evaluations.
//
// Use functional options like [WithTrace] when calling [Ast.Evaluate]
// rather than creating this struct directly.
type EvalOptions struct {
	trace bool
}

// EvalOptionFunc is a functional option for configuring policy evaluation.
type EvalOptionFunc func(*EvalOptions)

// WithTrace enables or disables trace output for a single evaluation.
//
// When enabled, detailed evaluation steps are printed to stdout.
// This overrides the default tracing setting from [WithDefaultTracing].
func WithTrace(trace bool) EvalOptionFunc {
	return func(o *EvalOptions) {
		o.trace = trace
	}
}

// Evaluate executes a query against the compiled policy AST.
//
// The queryStr specifies the Rego query to evaluate, typically binding a
// variable to a policy rule (e.g., "x = data.authz.allow"). The input
// provides the data available to the policy via the input document.
//
// Returns the first result from the query, which includes variable bindings.
// Returns a [common.PolicyError] if evaluation fails or produces no results.
//
// Example:
//
//	result, err := ast.Evaluate(ctx, "x = data.authz.allow", porcData)
//	if err != nil {
//	    // Handle evaluation error
//	}
//	allowed := result.Bindings["x"].(bool)
func (p *Ast) Evaluate(ctx context.Context, queryStr string, input interface{}, options ...EvalOptionFunc) (rego.Result, *common.PolicyError) {
	logger.Debug(agent, "Evaluate", "Enter")
	defer logger.Debug(agent, "Evaluate", "Exit")

	logger.Debugf(agent, "Evaluate", "input to rego: %+v", input)

	opts := &EvalOptions{trace: p.trace}
	for _, o := range options {
		o(opts)
	}

	// Build the query, then evaluate and deal with the results.
	query := rego.New(
		rego.Query(queryStr),
		rego.Compiler(p.compiler),
		rego.Input(input),
		rego.Trace(opts.trace),
	)

	results, err := query.Eval(ctx)
	if err != nil {
		logger.Debugf(agent, "Evaluate", "queryEval %+v", err)
		return rego.Result{}, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_EVALUATION_ERROR, Reason: err.Error()}
	} else if len(results) == 0 { // no results
		logger.Debugf(agent, "Evaluate", "no opa results: %s, input: %+v", p.name, input)
		return rego.Result{}, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_EVALUATION_ERROR, Reason: fmt.Sprintf("no opa results: %s, input: %+v", p.name, input)}
	}
	if opts.trace {
		regoTrace := new(strings.Builder)
		rego.PrintTraceWithLocation(regoTrace, query)
		logger.Trace(agent, "Evaluate", "rego trace:")
		fmt.Println(regoTrace.String()) // force internal format
		logger.Trace(agent, "Evaluate", "query results:")
		common.PrettyPrint(results)
	}

	return results[0], nil
}
