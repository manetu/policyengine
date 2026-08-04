//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"context"
	"testing"

	"github.com/manetu/policyengine/internal/core/backend/mock"
	"github.com/manetu/policyengine/pkg/core/types"
	"github.com/stretchr/testify/assert"
)

func TestFlattenSubs(t *testing.T) {
	tests := []struct {
		name      string
		principal map[string]interface{}
		expected  []string
	}{
		{
			name:      "subject only (no delegation)",
			principal: map[string]interface{}{Sub: "mrn:iam:id:alice"},
			expected:  []string{"mrn:iam:id:alice"},
		},
		{
			name: "single actor: [act.sub, sub]",
			principal: map[string]interface{}{
				Sub: "mrn:iam:id:alice",
				Act: map[string]interface{}{Sub: "mrn:iam:id:svc-a"},
			},
			// current actor first, subject last
			expected: []string{"mrn:iam:id:svc-a", "mrn:iam:id:alice"},
		},
		{
			name: "nested chain: [act.sub, act.act.sub, sub]",
			principal: map[string]interface{}{
				Sub: "mrn:iam:id:alice",
				Act: map[string]interface{}{
					Sub: "mrn:iam:id:svc-a",
					Act: map[string]interface{}{Sub: "mrn:iam:id:svc-b"},
				},
			},
			expected: []string{"mrn:iam:id:svc-a", "mrn:iam:id:svc-b", "mrn:iam:id:alice"},
		},
		{
			name:      "empty principal yields no subs",
			principal: map[string]interface{}{},
			expected:  nil,
		},
		{
			name: "blank subs are skipped",
			principal: map[string]interface{}{
				Sub: "mrn:iam:id:alice",
				Act: map[string]interface{}{Sub: ""},
			},
			expected: []string{"mrn:iam:id:alice"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, flattenSubs(tt.principal))
		})
	}
}

func TestFlatMergeContext(t *testing.T) {
	t.Run("merges resolved into ambient", func(t *testing.T) {
		existing := map[string]interface{}{"request": map[string]interface{}{"ip": "1.2.3.4"}}
		resolved := map[string]interface{}{"clearance": "secret"}
		out := flatMergeContext(existing, resolved)
		assert.Equal(t, map[string]interface{}{"ip": "1.2.3.4"}, out["request"])
		assert.Equal(t, "secret", out["clearance"])
	})

	t.Run("resolved wins on key collision", func(t *testing.T) {
		out := flatMergeContext(
			map[string]interface{}{"k": "ambient"},
			map[string]interface{}{"k": "resolved"})
		assert.Equal(t, "resolved", out["k"])
	})

	t.Run("nil/non-map existing is tolerated", func(t *testing.T) {
		out := flatMergeContext(nil, map[string]interface{}{"k": "v"})
		assert.Equal(t, map[string]interface{}{"k": "v"}, out)
	})

	t.Run("does not mutate the existing map", func(t *testing.T) {
		existing := map[string]interface{}{"k": "ambient"}
		flatMergeContext(existing, map[string]interface{}{"k": "resolved"})
		assert.Equal(t, "ambient", existing["k"])
	})
}

// TestResolveContext drives the Authorize-time enrichment stage end to end
// through the backend (the mock's "withcontext"/"networkerror" sentinels),
// covering the merge, failure, empty-result, and no-subs paths.
func TestResolveContext(t *testing.T) {
	pe := &PolicyEngine{backend: &mock.Backend{}}

	t.Run("non-empty resolve is flat-merged, ambient preserved", func(t *testing.T) {
		input := types.PORC{contextKey: map[string]interface{}{"ambient": 1}}
		pe.resolveContext(context.Background(), input, map[string]interface{}{Sub: "mrn:iam:id:alice-withcontext"})
		got, _ := input[contextKey].(map[string]interface{})
		assert.Equal(t, true, got["resolved"]) // from the resolver
		assert.Equal(t, 1, got["ambient"])     // ambient kept
	})

	t.Run("failed resolve attaches nothing", func(t *testing.T) {
		input := types.PORC{}
		pe.resolveContext(context.Background(), input, map[string]interface{}{Sub: "mrn:iam:id:networkerror"})
		assert.Nil(t, input[contextKey])
	})

	t.Run("empty resolve attaches nothing", func(t *testing.T) {
		input := types.PORC{}
		pe.resolveContext(context.Background(), input, map[string]interface{}{Sub: "mrn:iam:id:alice"})
		assert.Nil(t, input[contextKey])
	})

	t.Run("no subs short-circuits", func(t *testing.T) {
		input := types.PORC{}
		pe.resolveContext(context.Background(), input, map[string]interface{}{})
		assert.Nil(t, input[contextKey])
	})
}
