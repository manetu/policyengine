//
//  Copyright © Manetu Inc. All rights reserved.
//
// OPA abstraction for compiling and evaluating policies

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

// Builtins is a set of builtin function names
type Builtins map[string]struct{}

// Compiler represents a compiler abstraction for converting textual REGO policies to ASTs
type Compiler struct {
	options *CompilerOptions
}

// Ast is an Abstract Syntax Tree for compiled REGO policies
type Ast struct {
	name     string
	compiler *ast.Compiler
	trace    bool
}

// Modules is a map of module name to module source code
type Modules map[string]string

// CompilerOptions contains configuration options for the compiler.
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

// CompilerOptionFunc is a function that modifies CompilerOptions.
type CompilerOptionFunc func(*CompilerOptions)

// WithRegoVersion sets the rego version for the compiler.
func WithRegoVersion(regoVersion ast.RegoVersion) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.regoVersion = regoVersion
	}
}

// WithCapabilities sets the rego Capabilities options for the compiler.  This must come before WithUnsafeBuiltins,
// when both are used.
func WithCapabilities(capabilities *ast.Capabilities) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.capabilities = capabilities
	}
}

// WithDefaultCapabilities resets the capabilities back to the default
func WithDefaultCapabilities() CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.capabilities = ast.CapabilitiesForThisVersion()
	}
}

// WithUnsafeBuiltins sets the list of unsafe builtin functions to be removed from the compiler.  This must come
// after WithCapabilities, when used
func WithUnsafeBuiltins(unsafeBuiltins Builtins) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		// see: https://github.com/open-policy-agent/opa/security/advisories/GHSA-f524-rf33-2jjr
		o.capabilities.Builtins = filter(o.capabilities.Builtins, func(builtin *ast.Builtin) bool { _, ok := unsafeBuiltins[builtin.Name]; return !ok })
	}
}

// WithDefaultTracing sets the default tracing in effect during evaluation that is used if not
// explicitly set by the Evaluate() option 'WithTrace'. Defaults to log tracing level.
func WithDefaultTracing(trace bool) CompilerOptionFunc {
	return func(o *CompilerOptions) {
		o.trace = trace
	}
}

// NewCompiler creates a new Compiler with the specified options.
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

// Clone creates a new instance of Compiler based on the current configuration, optionally applying additional options.
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

// Compile compiles the provided modules and returns a Ast object, suitable for reusable evaluation.
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

// EvalOptions contains configuration options for policy evaluation.
type EvalOptions struct {
	trace bool
}

// EvalOptionFunc is a function that modifies EvalOptions.
type EvalOptionFunc func(*EvalOptions)

// WithTrace configures whether to enable trace output during policy evaluation.
func WithTrace(trace bool) EvalOptionFunc {
	return func(o *EvalOptions) {
		o.trace = trace
	}
}

// Evaluate evaluates the compiled AST with the given input and query string, returning the result or a PolicyError.
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
