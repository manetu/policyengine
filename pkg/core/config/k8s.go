//
//  Copyright © Manetu Inc. All rights reserved.
//

package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	k8sLabels      map[string]string
	k8sAnnotations map[string]string
	k8sLabelsOnce  sync.Once
	k8sAnnotsOnce  sync.Once
)

// resetK8sCache clears cached Downward API data so it will be re-read.
// Intended for testing only.
func resetK8sCache() {
	k8sLabels = nil
	k8sAnnotations = nil
	k8sLabelsOnce = sync.Once{}
	k8sAnnotsOnce = sync.Once{}
}

// podinfoPath returns the configured Downward API podinfo directory.
func podinfoPath() string {
	return VConfig.GetString(AuditK8sPodinfo)
}

// parseDownwardAPIFile reads a Kubernetes Downward API file and returns a map
// of key-value pairs. The expected format is one key="value" per line.
// Returns nil if the file does not exist.
func parseDownwardAPIFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is constructed from trusted config + fixed filenames
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Remove surrounding quotes from the value
		value = strings.Trim(value, "\"")
		result[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// getK8sLabels returns cached Kubernetes pod labels from the Downward API file.
// Returns nil if the file does not exist (i.e., not running in Kubernetes or
// the Downward API volume is not configured).
func getK8sLabels() map[string]string {
	k8sLabelsOnce.Do(func() {
		p := filepath.Join(podinfoPath(), "labels")
		labels, err := parseDownwardAPIFile(p)
		if err != nil {
			logger.SysWarnf("failed to read k8s labels from %s: %v", p, err)
			return
		}
		k8sLabels = labels
	})
	return k8sLabels
}

// getK8sAnnotations returns cached Kubernetes pod annotations from the Downward API file.
// Returns nil if the file does not exist (i.e., not running in Kubernetes or
// the Downward API volume is not configured).
func getK8sAnnotations() map[string]string {
	k8sAnnotsOnce.Do(func() {
		p := filepath.Join(podinfoPath(), "annotations")
		annots, err := parseDownwardAPIFile(p)
		if err != nil {
			logger.SysWarnf("failed to read k8s annotations from %s: %v", p, err)
			return
		}
		k8sAnnotations = annots
	})
	return k8sAnnotations
}
