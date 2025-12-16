//
//  Copyright © Manetu Inc. All rights reserved.
//

package opa

import (
	"context"
	"io"
	"os"
	"testing"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

func TestNewCompiler(t *testing.T) {
	compiler := NewCompiler()
	assert.NotNil(t, compiler)
}

func TestCompileSuccess(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
default allow = false
allow = true { input.user == "admin" }
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)
	assert.NotNil(t, ast)
	assert.Equal(t, "test-policy", ast.name)
	assert.NotNil(t, ast.compiler)
}

func TestCompileWithSyntaxError(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
default allow = false
allow = true { this is invalid syntax }
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.Error(t, err)
	assert.Nil(t, ast)
}

func TestCompileWithCompilationError(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
allow = true { data.undefined_function() }
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.Error(t, err)
	assert.Nil(t, ast)
}

func TestCompileWithUnsafeBuiltins(t *testing.T) {
	// First try without allowing unsafe builtins
	compiler := NewCompiler(WithUnsafeBuiltins(map[string]struct{}{
		"http.send": {},
	}))

	modules := Modules{
		"test.rego": `
package authz
allow = true {
	response := http.send({"method": "get", "url": "http://example.com"})
	response.status_code == 200
}
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.Error(t, err)
	assert.Nil(t, ast)
	assert.Contains(t, err.Error(), "undefined function http.send")

	// Now allow the unsafe builtin
	compiler2 := NewCompiler()
	ast2, err2 := compiler2.Compile("test-policy", modules)
	assert.NoError(t, err2)
	assert.NotNil(t, ast2)

	// Now test that a clone of the instance with UnsafeBuiltins inherits the Capabilities
	compiler3 := compiler.Clone()
	ast3, err3 := compiler3.Compile("test-policy", modules)
	assert.Error(t, err3)
	assert.Nil(t, ast3)
	assert.Contains(t, err3.Error(), "undefined function http.send")

	// Now Clone again, but override the builtins so that http.send is now allowed
	compiler4 := compiler.Clone(WithDefaultCapabilities())
	ast4, err4 := compiler4.Compile("test-policy", modules)
	assert.NoError(t, err4)
	assert.NotNil(t, ast4)
}

func TestEvaluateSuccess(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
default allow = false
allow = true { input.user == "admin" }
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	// Test with admin user
	input := map[string]interface{}{
		"user": "admin",
	}

	result, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.Nil(t, policyErr)
	assert.Equal(t, true, result.Expressions[0].Value)

	// Test with non-admin user
	input = map[string]interface{}{
		"user": "guest",
	}

	result, policyErr = ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.Nil(t, policyErr)
	assert.Equal(t, false, result.Expressions[0].Value)
}

func TestEvaluateWithNoResults(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
# No allow rule defined
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	input := map[string]interface{}{
		"user": "admin",
	}

	_, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.NotNil(t, policyErr)
	assert.Equal(t, events.AccessRecord_BundleReference_EVALUATION_ERROR, policyErr.ReasonCode)
	assert.Contains(t, policyErr.Reason, "no opa results")
}

func TestEvaluateWithRuntimeError(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
allow = true {
	# This will cause a runtime error - division by zero
	x := 1 / 0
}
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	input := map[string]interface{}{
		"test": "data",
	}

	_, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.NotNil(t, policyErr)
	assert.Equal(t, events.AccessRecord_BundleReference_EVALUATION_ERROR, policyErr.ReasonCode)
}

func TestEvaluateWithComplexInput(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
default allow = false

allow = true {
	input.principal.roles[_] == "admin"
	input.operation == "write"
	input.resource.classification == "public"
}
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	// Test successful case
	input := map[string]interface{}{
		"principal": map[string]interface{}{
			"roles": []string{"user", "admin"},
		},
		"operation": "write",
		"resource": map[string]interface{}{
			"classification": "public",
		},
	}

	result, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.Nil(t, policyErr)
	assert.Equal(t, true, result.Expressions[0].Value)

	// Test failure case - wrong classification
	input = map[string]interface{}{
		"principal": map[string]interface{}{
			"roles": []string{"user", "admin"},
		},
		"operation": "write",
		"resource": map[string]interface{}{
			"classification": "private",
		},
	}

	result, policyErr = ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.Nil(t, policyErr)
	assert.Equal(t, false, result.Expressions[0].Value)
}

func TestEvaluateWithIntegerResult(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"test.rego": `
package authz
default allow = 0

allow = 1 { input.action == "grant" }
allow = -1 { input.action == "deny" }
allow = 2 { input.action == "visitor" }
`,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	tests := []struct {
		action   string
		expected string
	}{
		{"grant", "1"},
		{"deny", "-1"},
		{"visitor", "2"},
		{"unknown", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			input := map[string]interface{}{
				"action": tt.action,
			}

			result, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
			assert.Nil(t, policyErr)
			assert.NotNil(t, result.Expressions[0].Value)
			// OPA returns numbers as json.Number - verify it can convert to string
			resultStr := ""
			switch v := result.Expressions[0].Value.(type) {
			case string:
				resultStr = v
			default:
				resultStr = v.(interface{ String() string }).String()
			}
			assert.Equal(t, tt.expected, resultStr)
		})
	}
}

func TestWithRegoVersion(t *testing.T) {
	compiler := NewCompiler(WithRegoVersion(ast.RegoV1))
	assert.NotNil(t, compiler)
	assert.Equal(t, ast.RegoV1, compiler.options.regoVersion)
}

func TestWithCapabilities(t *testing.T) {
	caps := ast.CapabilitiesForThisVersion()
	compiler := NewCompiler(WithCapabilities(caps))
	assert.NotNil(t, compiler)
	assert.Equal(t, caps, compiler.options.capabilities)
}

func captureStdout(f func()) string {
	originalStdout := os.Stdout
	defer func() {
		os.Stdout = originalStdout
	}()
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	err := w.Close()
	if err != nil {
		return ""
	}
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestTracing(t *testing.T) {
	modules := Modules{
		"test.rego": `
package authz
default allow = false
allow = true { input.user == "admin" }
`,
	}

	input := map[string]interface{}{
		"user": "admin",
	}

	t.Run("verify default settings emit no traces", func(t *testing.T) {
		compiler := NewCompiler()

		instance, err := compiler.Compile("test-policy", modules)
		assert.NoError(t, err)

		output := captureStdout(func() {
			result, policyErr := instance.Evaluate(context.Background(), "data.authz.allow", input)
			assert.Nil(t, policyErr)
			assert.Equal(t, true, result.Expressions[0].Value)
		})
		assert.Equal(t, output, "")
	})

	t.Run("as compiler option", func(t *testing.T) {
		compiler := NewCompiler(WithDefaultTracing(true))

		instance, err := compiler.Compile("test-policy", modules)
		assert.NoError(t, err)

		output := captureStdout(func() {
			result, policyErr := instance.Evaluate(context.Background(), "data.authz.allow", input)
			assert.Nil(t, policyErr)
			assert.Equal(t, true, result.Expressions[0].Value)
		})
		assert.Contains(t, output, "Enter data.authz.allow")
	})

	t.Run("as eval option", func(t *testing.T) {
		compiler := NewCompiler()

		instance, err := compiler.Compile("test-policy", modules)
		assert.NoError(t, err)

		output := captureStdout(func() {
			result, policyErr := instance.Evaluate(context.Background(), "data.authz.allow", input, WithTrace(true))
			assert.Nil(t, policyErr)
			assert.Equal(t, true, result.Expressions[0].Value)
		})
		assert.Contains(t, output, "Enter data.authz.allow")
	})

}

func TestCompileMultipleModules(t *testing.T) {
	compiler := NewCompiler()

	modules := Modules{
		"module1.rego": `
package authz
import data.utils
default allow = false
allow = true { utils.is_admin(input.user) }
`,
		"module2.rego": `
package utils
is_admin(user) { user == "admin" }
`,
	}

	ast, err := compiler.Compile("multi-module-policy", modules)
	assert.NoError(t, err)
	assert.NotNil(t, ast)

	input := map[string]interface{}{
		"user": "admin",
	}

	result, policyErr := ast.Evaluate(context.Background(), "data.authz.allow", input)
	assert.Nil(t, policyErr)
	assert.Equal(t, true, result.Expressions[0].Value)
}

func TestFilterFunction(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := filter([]int{}, func(i int) bool { return i > 5 })
		assert.Empty(t, result)
	})

	t.Run("no matches", func(t *testing.T) {
		result := filter([]int{1, 2, 3}, func(i int) bool { return i > 10 })
		assert.Empty(t, result)
	})

	t.Run("all match", func(t *testing.T) {
		result := filter([]int{1, 2, 3}, func(i int) bool { return i > 0 })
		assert.Equal(t, []int{1, 2, 3}, result)
	})

	t.Run("some match", func(t *testing.T) {
		result := filter([]int{1, 5, 10, 15}, func(i int) bool { return i > 7 })
		assert.Equal(t, []int{10, 15}, result)
	})

	t.Run("string slice", func(t *testing.T) {
		result := filter([]string{"foo", "bar", "baz"}, func(s string) bool { return s != "bar" })
		assert.Equal(t, []string{"foo", "baz"}, result)
	})
}
