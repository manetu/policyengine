//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

var yamlLineRegex = regexp.MustCompile(`line (\d+)`)

// lintYAML validates YAML syntax for the given raw bytes and returns any diagnostics.
// key is the logical identifier (file path or name) used to populate Location.File.
func lintYAML(data []byte, key string) []Diagnostic {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		d := Diagnostic{
			Source:   SourceYAML,
			Severity: SeverityError,
			Location: Location{File: key},
			Message:  err.Error(),
		}
		// yaml.v3 embeds line info in the error string: "yaml: line N: ..."
		if m := yamlLineRegex.FindStringSubmatch(err.Error()); len(m) == 2 {
			if line, e := strconv.Atoi(m[1]); e == nil {
				d.Location.Start.Line = line
			}
		}
		return []Diagnostic{d}
	}
	return nil
}
