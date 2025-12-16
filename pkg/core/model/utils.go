//
//  Copyright © Manetu Inc. All rights reserved.
//

package model

import (
	"encoding/json"
	"fmt"

	"github.com/manetu/policyengine/pkg/common"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// ToJSON converts string-based annotations to JSON
func ToJSON(input map[string]string) (Annotations, *common.PolicyError) {
	output := Annotations{}
	for k, v := range input {
		var x interface{}
		err := json.Unmarshal([]byte(v), &x)
		if err != nil {
			return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_INVALPARAM_ERROR, Reason: fmt.Sprintf("bad annotation (err-%s)", err.Error())}
		}
		output[k] = x
	}

	return output, nil
}

// UnsafeToJSON converts string-based annotations to JSON, panics on error.  Should only be used in tests.
func UnsafeToJSON(input map[string]string) Annotations {
	annotations, err := ToJSON(input)
	if err != nil {
		panic(err)
	}
	return annotations
}
