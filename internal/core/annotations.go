//
// Copyright © Manetu Inc.  All rights reserved.
//

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
)

/**********************************************************************************************************************************
 In general errors while fetching annotations could be of any kind. E.g.,  network failure, bad syntax. These annotations
 will be removed and policy evaluation will proceed without them. Policies that require these annotations should fail evaluation.
**********************************************************************************************************************************/

func (pe *PolicyEngine) getScopesAnnotations(ctx context.Context, scopes []string) []model.RichAnnotations {
	if len(scopes) == 0 {
		return nil
	}

	annotations := make([]model.RichAnnotations, len(scopes))
	errs := make([]*common.PolicyError, len(scopes))

	var wg sync.WaitGroup
	wg.Add(len(scopes))

	for i, mrn := range scopes {
		go func(i int, scopeMrn string) {
			defer wg.Done()

			scope, err := pe.backend.GetScope(ctx, scopeMrn)
			if err != nil {
				//annotations for this scope will remain nil
				logger.Debugf(agent, "getScopesAnnotations", "%s (err-%s)", scopeMrn, err)
				errs[i] = err
				return
			}

			annotations[i] = scope.Annotations
		}(i, mrn)
	}
	wg.Wait()

	return annotations
}

// in addition to annotations for a group, also fetch its roles to be consolidated with independent roles into a consolidated
// annotations set for the roles
func (pe *PolicyEngine) getGroupsAnnotations(ctx context.Context, groups []string) ([][]string, []model.RichAnnotations) {
	if len(groups) == 0 {
		return nil, nil
	}

	roles := make([][]string, len(groups))
	annotations := make([]model.RichAnnotations, len(groups))

	var wg sync.WaitGroup
	wg.Add(len(groups))

	for i, mrn := range groups {
		go func(j int, groupMrn string) {
			defer wg.Done()
			group, err := pe.backend.GetGroup(ctx, groupMrn)
			if err != nil {
				//roles and annotations for this group will remain nil
				logger.Debugf(agent, "getGroupsAnnotations", "%s (err-%s)", groupMrn, err)
				return
			}
			roles[j] = group.Roles
			annotations[j] = group.Annotations
		}(i, mrn)
	}
	wg.Wait()

	return roles, annotations
}

func (pe *PolicyEngine) getRolesAnnotations(ctx context.Context, roles []string) []model.RichAnnotations {
	if len(roles) == 0 {
		return nil
	}

	annotations := make([]model.RichAnnotations, len(roles))

	var wg sync.WaitGroup
	wg.Add(len(roles))

	for i, mrn := range roles {
		go func(j int, roleMrn string) {
			defer wg.Done()

			role, err := pe.backend.GetRole(ctx, roleMrn)
			if err != nil {
				//annotations for this role will remain nil
				logger.Debugf(agent, "getRolesAnnotations", "%s (err-%s)", roleMrn, err)
				return
			}

			annotations[j] = role.Annotations
		}(i, mrn)
	}
	wg.Wait()

	return annotations
}

// mergeRichAnnotations merges annotations from a lower-priority source into a higher-priority destination.
// The merge strategy is determined by the higher-priority entry, falling back to the lower-priority entry's
// strategy, and finally to the default strategy (deep merge).
//
// Parameters:
//   - lower: annotations from lower-priority source (e.g., role)
//   - higher: annotations from higher-priority source (e.g., group)
//   - defaultStrategy: the default merge strategy to use when none specified
//
// Returns the merged RichAnnotations.
func mergeRichAnnotations(lower, higher model.RichAnnotations, defaultStrategy string) model.RichAnnotations {
	if lower == nil && higher == nil {
		return make(model.RichAnnotations)
	}

	if defaultStrategy == "" {
		defaultStrategy = model.DefaultMergeStrategy
	}

	result := make(model.RichAnnotations)

	// Copy all lower entries first
	for k, entry := range lower {
		result[k] = entry
	}

	// MergeStrategy higher entries
	for k, higherEntry := range higher {
		if lowerEntry, exists := result[k]; exists {
			// Key exists in both - determine strategy and merge
			strategy := determineStrategy(lowerEntry.MergeStrategy, higherEntry.MergeStrategy, defaultStrategy)
			mergedValue := mergeValues(lowerEntry.Value, higherEntry.Value, strategy)
			result[k] = model.AnnotationEntry{
				Value:         mergedValue,
				MergeStrategy: higherEntry.MergeStrategy, // Preserve strategy from higher priority
			}
		} else {
			// Key only in higher - just copy
			result[k] = higherEntry
		}
	}

	return result
}

// determineStrategy returns the merge strategy to use.
// Priority: higher's strategy > lower's strategy > default
func determineStrategy(lowerStrategy, higherStrategy, defaultStrategy string) string {
	if higherStrategy != "" {
		return higherStrategy
	}
	if lowerStrategy != "" {
		return lowerStrategy
	}
	return defaultStrategy
}

// mergeValues merges two values according to the specified strategy.
func mergeValues(lower, higher interface{}, strategy string) interface{} {
	// Type mismatch: higher always wins
	if !sameType(lower, higher) {
		return higher
	}

	switch strategy {
	case model.MergeReplace:
		return higher

	case model.MergeAppend:
		return mergeAppend(lower, higher)

	case model.MergePrepend:
		return mergePrepend(lower, higher)

	case model.MergeUnion:
		return mergeUnion(lower, higher)

	case model.MergeDeep:
		fallthrough
	default:
		return mergeDeep(lower, higher)
	}
}

// sameType checks if two values have compatible types for merging.
func sameType(a, b interface{}) bool {
	switch a.(type) {
	case []interface{}:
		_, ok := b.([]interface{})
		return ok
	case map[string]interface{}:
		_, ok := b.(map[string]interface{})
		return ok
	default:
		// a is a scalar - b must also be a scalar (not array or object)
		switch b.(type) {
		case []interface{}, map[string]interface{}:
			return false
		default:
			return true
		}
	}
}

// mergeDeep performs a deep recursive merge.
// Arrays: higher elements first, then lower
// Objects: recursive merge with higher keys winning on conflict
// Scalars: higher wins
func mergeDeep(lower, higher interface{}) interface{} {
	switch h := higher.(type) {
	case []interface{}:
		l := lower.([]interface{})
		result := make([]interface{}, 0, len(h)+len(l))
		result = append(result, h...)
		result = append(result, l...)
		return result

	case map[string]interface{}:
		l := lower.(map[string]interface{})
		result := make(map[string]interface{})
		for k, v := range l {
			result[k] = v
		}
		for k, v := range h {
			if existing, ok := result[k]; ok && sameType(existing, v) {
				result[k] = mergeDeep(existing, v)
			} else {
				result[k] = v
			}
		}
		return result

	default:
		return higher
	}
}

// mergeAppend concatenates arrays with higher first, shallow merges objects with higher winning.
func mergeAppend(lower, higher interface{}) interface{} {
	switch h := higher.(type) {
	case []interface{}:
		l := lower.([]interface{})
		result := make([]interface{}, 0, len(h)+len(l))
		result = append(result, h...)
		result = append(result, l...)
		return result

	case map[string]interface{}:
		l := lower.(map[string]interface{})
		result := make(map[string]interface{})
		for k, v := range l {
			result[k] = v
		}
		for k, v := range h {
			result[k] = v // higher wins on collision
		}
		return result

	default:
		return higher
	}
}

// mergePrepend concatenates arrays with lower first, shallow merges objects with lower winning.
func mergePrepend(lower, higher interface{}) interface{} {
	switch h := higher.(type) {
	case []interface{}:
		l := lower.([]interface{})
		result := make([]interface{}, 0, len(l)+len(h))
		result = append(result, l...)
		result = append(result, h...)
		return result

	case map[string]interface{}:
		l := lower.(map[string]interface{})
		result := make(map[string]interface{})
		for k, v := range h {
			result[k] = v
		}
		for k, v := range l {
			result[k] = v // lower wins on collision
		}
		return result

	default:
		return lower // scalar: lower wins
	}
}

// mergeUnion creates a deduplicated set from arrays, deep merges objects.
func mergeUnion(lower, higher interface{}) interface{} {
	switch h := higher.(type) {
	case []interface{}:
		l := lower.([]interface{})
		seen := make(map[string]bool)
		result := make([]interface{}, 0)

		// Add higher elements first (maintaining order within higher)
		for _, v := range h {
			key := toComparableKey(v)
			if !seen[key] {
				seen[key] = true
				result = append(result, v)
			}
		}

		// Add lower elements not already present
		for _, v := range l {
			key := toComparableKey(v)
			if !seen[key] {
				seen[key] = true
				result = append(result, v)
			}
		}

		return result

	case map[string]interface{}:
		// For objects, union behaves like deep merge
		return mergeDeep(lower, higher)

	default:
		return higher
	}
}

// toComparableKey creates a string key for deduplication.
// Works reliably for primitives; objects get JSON serialization.
func toComparableKey(v interface{}) string {
	switch val := v.(type) {
	case string:
		return "s:" + val
	case float64:
		return fmt.Sprintf("n:%v", val)
	case bool:
		return fmt.Sprintf("b:%v", val)
	case nil:
		return "null"
	default:
		// For arrays/objects, use JSON serialization
		b, _ := json.Marshal(val)
		return "j:" + string(b)
	}
}

// mergeAnnotations is a compatibility wrapper that converts plain annotations
// to RichAnnotations, merges them, and returns plain annotations.
// This is used for PORC annotations which come in as map[string]interface{}.
func mergeAnnotations(from, into model.RichAnnotations) model.RichAnnotations {
	return mergeRichAnnotations(from, into, model.DefaultMergeStrategy)
}

// plainToRich converts plain annotations (from PORC) to RichAnnotations.
// All entries get empty merge strategy (will use default).
func plainToRich(plain map[string]interface{}) model.RichAnnotations {
	if plain == nil {
		return nil
	}
	result := make(model.RichAnnotations, len(plain))
	for k, v := range plain {
		result[k] = model.AnnotationEntry{Value: v}
	}
	return result
}

// GetAnnotations gets resultant annotations for an identity using the hierarchy
//
//	passed annotation (e.g., from PORC) > scope > group > (identity's roles + group's roles)
//
// where > signifies decreasing precedence in the merge process.
// Returns plain Annotations suitable for use in PORC.
func (pe *PolicyEngine) GetAnnotations(ctx context.Context, annots map[string]interface{}, scopes, groups, roles []string) map[string]interface{} {
	// Convert PORC annotations to RichAnnotations
	result := plainToRich(annots)
	if result == nil {
		result = make(model.RichAnnotations)
	}

	// merge scope annotations (scope is higher priority than groups/roles)
	if len(scopes) > 0 {
		scopeAnnotations := pe.getScopesAnnotations(ctx, scopes)

		for _, annotation := range scopeAnnotations {
			if annotation != nil {
				result = mergeRichAnnotations(annotation, result, model.DefaultMergeStrategy)
			}
		}
	}

	//..process given groups merging annotations and collecting roles
	var (
		groupRoles       [][]string
		groupAnnotations []model.RichAnnotations
	)

	roleSet := make(map[string]struct{})

	// fetch group annotations and collect roles for processing
	if len(groups) > 0 {
		// get all the groups objects from given groups ...
		groupRoles, groupAnnotations = pe.getGroupsAnnotations(ctx, groups)

		//... and mark roles
		for i := range groupAnnotations {
			for _, role := range groupRoles[i] {
				roleSet[role] = struct{}{}
			}
		}

		// merge group annotations (groups are higher priority than roles)
		for _, annotation := range groupAnnotations {
			if annotation != nil {
				result = mergeRichAnnotations(annotation, result, model.DefaultMergeStrategy)
			}
		}
	}

	if len(roles) > 0 {
		// add all given roles into the set
		for _, role := range roles {
			roleSet[role] = struct{}{}
		}
	}

	// get cumulative roles from given roles and those from groups
	roles = make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}

	//..process cumulative roles and merge annotations (roles are lowest priority)
	if len(roles) > 0 {
		// get the roles info from IAM
		roleAnnotations := pe.getRolesAnnotations(ctx, roles)

		//...and merge annotations from roles (roles are lower priority than current result)
		for _, annotation := range roleAnnotations {
			if annotation != nil {
				result = mergeRichAnnotations(annotation, result, model.DefaultMergeStrategy)
			}
		}
	}

	// Convert to plain annotations for PORC
	return result.ToAnnotations()
}
