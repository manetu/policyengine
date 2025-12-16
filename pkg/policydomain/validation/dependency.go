//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"fmt"
	"strings"
)

// DependencyResolver handles dependency resolution with cycle detection
type DependencyResolver struct {
	resolver *ReferenceResolver
}

// NewDependencyResolver creates a new dependency resolver
func NewDependencyResolver(resolver *ReferenceResolver) *DependencyResolver {
	return &DependencyResolver{
		resolver: resolver,
	}
}

// ResolveDependencies resolves all dependencies for a given set of input dependencies
func (dr *DependencyResolver) ResolveDependencies(model DomainModel, dependencies []string) ([]string, error) {
	visited := make(map[string]bool)
	path := make([]string, 0)
	return dr.resolveDependenciesWithCycleDetection(model, dependencies, visited, path)
}

// resolveDependenciesWithCycleDetection performs dependency resolution with cycle detection
func (dr *DependencyResolver) resolveDependenciesWithCycleDetection(model DomainModel, input []string, visited map[string]bool, path []string) ([]string, error) {
	var result []string

	for _, dependency := range input {
		resolved, err := dr.resolveSingleDependency(model, dependency, visited, path)
		if err != nil {
			return nil, err
		}
		result = append(result, resolved...)
	}

	return removeDuplicates(result), nil
}

// resolveSingleDependency resolves a single dependency and its transitive dependencies
func (dr *DependencyResolver) resolveSingleDependency(model DomainModel, dependency string, visited map[string]bool, path []string) ([]string, error) {
	var result []string
	result = append(result, dependency)

	// Create qualified reference for cycle detection
	qualifiedRef := dr.resolver.QualifyReference(dependency, model.GetName())

	// Check for cycles
	if err := dr.checkForCycle(qualifiedRef, visited, path); err != nil {
		return nil, err
	}

	// Mark as visited and add to path for cycle detection
	visited[qualifiedRef] = true
	newPath := append(path, qualifiedRef)

	// Resolve the dependency
	targetDomain, targetModel, depID, err := dr.resolver.ResolveReference(dependency, model.GetName(), "library")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependency '%s': %w", dependency, err)
	}

	// Get the library
	library, err := dr.getLibrary(targetModel, depID)
	if err != nil {
		return nil, fmt.Errorf("failed to get library '%s' in domain '%s': %w", depID, targetDomain, err)
	}

	// Recursively resolve transitive dependencies
	transitive, err := dr.resolveDependenciesWithCycleDetection(targetModel, library.GetDependencies(), visited, newPath)
	if err != nil {
		return nil, err
	}

	// Qualify transitive dependencies
	for _, dep := range transitive {
		qualifiedDep := dr.qualifyDependency(dep, targetDomain)
		result = append(result, qualifiedDep)
	}

	// Remove from visited set (backtrack)
	delete(visited, qualifiedRef)

	return result, nil
}

// checkForCycle detects if adding a dependency would create a cycle
func (dr *DependencyResolver) checkForCycle(qualifiedRef string, visited map[string]bool, path []string) error {
	if !visited[qualifiedRef] {
		return nil // No cycle
	}

	// Build cycle path for error reporting
	cycleStart := dr.findCycleStart(qualifiedRef, path)
	var cyclePath []string
	if cycleStart >= 0 {
		cyclePath = append(path[cycleStart:], qualifiedRef)
	} else {
		cyclePath = append(path, qualifiedRef)
	}

	return fmt.Errorf("circular dependency detected: %s", strings.Join(cyclePath, " → "))
}

// findCycleStart finds where a cycle begins in the path
func (dr *DependencyResolver) findCycleStart(qualifiedRef string, path []string) int {
	for i, dep := range path {
		if dep == qualifiedRef {
			return i
		}
	}
	return -1
}

// getLibrary safely retrieves a library from a domain model
func (dr *DependencyResolver) getLibrary(model DomainModel, libID string) (PolicyEntity, error) {
	libraries := model.GetPolicyLibraries()
	library, exists := libraries[libID]
	if !exists {
		return nil, fmt.Errorf("library '%s' not found", libID)
	}
	return library, nil
}

// qualifyDependency ensures a dependency is properly qualified with domain
func (dr *DependencyResolver) qualifyDependency(dependency, targetDomain string) string {
	if strings.Contains(dependency, "/") {
		return dependency // Already qualified
	}
	return fmt.Sprintf("%s/%s", targetDomain, dependency)
}

// Helper function to remove duplicates
func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, val := range slice {
		if !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}
	return result
}
