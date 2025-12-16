//
//  Copyright © Manetu Inc. All rights reserved.
//

package version

// These variables are set at build time via -ldflags
var (
	// Version is the release version (e.g., v1.0.0) or git ref for dev builds
	Version = "dev"
)

// GetVersion returns the current version string
func GetVersion() string {
	return Version
}
