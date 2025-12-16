//
//  Copyright © Manetu Inc. All rights reserved.
//

package common

import (
	"encoding/json"
	"fmt"
)

// PrettyPrint outputs a readable JSON representation of the provided data structure.
func PrettyPrint(data interface{}) {
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%s \n", p)
	}
}
