//
// Copyright © Manetu Inc.  All rights reserved.
//

package core

import (
	"context"
	"sync"

	"github.com/manetu/policyengine/pkg/common"
)

/**********************************************************************************************************************************
 In general errors while fetching annotations could be of any kind. E.g.,  network failure, bad syntax. These annotations
 will be removed and policy evaluation will proceed without them. Policies that require these annotations should fail evaluation.
**********************************************************************************************************************************/

func (pe *PolicyEngine) getScopesAnnotations(ctx context.Context, scopes []string) []map[string]interface{} {
	if len(scopes) == 0 {
		return nil
	}

	annotations := make([]map[string]interface{}, len(scopes))
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
func (pe *PolicyEngine) getGroupsAnnotations(ctx context.Context, groups []string) ([][]string, []map[string]interface{}) {
	if len(groups) == 0 {
		return nil, nil
	}

	roles := make([][]string, len(groups))
	annotations := make([]map[string]interface{}, len(groups))

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

func (pe *PolicyEngine) getRolesAnnotations(ctx context.Context, roles []string) []map[string]interface{} {
	if len(roles) == 0 {
		return nil
	}

	annotations := make([]map[string]interface{}, len(roles))

	var wg sync.WaitGroup
	wg.Add(len(roles))

	for i, mrn := range roles {
		go func(j int, roleMrn string) {
			defer wg.Done()

			role, err := pe.backend.GetRole(ctx, roleMrn)
			if err != nil {
				//annotations for this group will remain nil
				logger.Debugf(agent, "getRolesAnnotations", "%s (err-%s)", roleMrn, err)
				return
			}

			annotations[j] = role.Annotations
		}(i, mrn)
	}
	wg.Wait()

	return annotations
}

func mergeAnnotations(from, into map[string]interface{}) map[string]interface{} {
	if from == nil && into == nil {
		return make(map[string]interface{})
	}

	if into == nil {
		into = make(map[string]interface{})
	}

	for k, v := range from {
		if _, ok := into[k]; ok {
			continue
		}
		into[k] = v
	}

	return into
}

// GetAnnotations gets resultant annotations for an identity using the hierarchy
//
//	passed annotation (e.g., from PORC) > scope > (identity's roles + group's roles) > group
//
// where > signifies decreasing precedence in the merge process. In particular, an annotation
// found in passed annotations cannot be overridden
func (pe *PolicyEngine) GetAnnotations(ctx context.Context, annots map[string]interface{}, scopes, groups, roles []string) map[string]interface{} {
	if annots == nil {
		annots = make(map[string]interface{})
	}

	// merge scope annotations
	if len(scopes) > 0 {
		scopeAnnotations := pe.getScopesAnnotations(ctx, scopes)

		//...and merge annotations from scopes
		for _, annotation := range scopeAnnotations {
			if annotation != nil {
				annots = mergeAnnotations(annotation, annots)
			}
		}
	}

	//..process given groups merging annotations and collecting roles
	var (
		groupRoles       [][]string
		groupAnnotations []map[string]interface{}
	)

	roleSet := make(map[string]struct{})

	// merge group annotations and get all the roles for processing
	if len(groups) > 0 {
		// get all the groups objects from given groups ...
		groupRoles, groupAnnotations = pe.getGroupsAnnotations(ctx, groups)

		//... and mark roles
		for i := range groupAnnotations {
			for _, role := range groupRoles[i] {
				roleSet[role] = struct{}{}
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

	//..process cumulative roles and merge annotations
	if len(roles) > 0 {
		// get the roles info from IAM
		roleAnnotations := pe.getRolesAnnotations(ctx, roles)

		//...and merge annotations from roles
		for _, annotation := range roleAnnotations {
			if annotation != nil {
				annots = mergeAnnotations(annotation, annots)
			}
		}
	}

	// ... finally merge group annotations
	for _, annotation := range groupAnnotations {
		if annotation != nil {
			annots = mergeAnnotations(annotation, annots)
		}
	}

	return annots
}
