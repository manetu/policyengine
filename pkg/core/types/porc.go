//
//  Copyright © Manetu Inc. All rights reserved.
//

package types

import (
	"encoding/json"
	"errors"
)

// AnyPORC allows a PORC expression to be submitted as either an unparsed JSON string, or an
// unmarshalled map.  This allows the caller to chose between convenience and efficiency.
type AnyPORC interface{}

// PORC (short for (P)rincipal (O)peration (R)esource (C)context) is a structure representing
// the input for authorization decisions.
type PORC map[string]interface{}

// UnmarshalPORC parses a JSON string, if required, into a decoded PORC map.
// If the input is already an unmarshalled map, it's just passed through
func UnmarshalPORC(input AnyPORC) (PORC, error) {

	switch input := input.(type) {
	case string:
		porc := make(PORC)
		// Now unmarshal into the map.
		err := json.Unmarshal([]byte(input), &porc)
		if err != nil {
			return nil, err
		}

		return porc, nil
	case map[string]interface{}:
		return input, nil
	default:
		return nil, errors.New("invalid type")
	}
}
