//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"io"
	"log"
	"os"
)

func getInputExpression(path string) string {
	var f *os.File
	var err error
	if path == "-" || path == "" {
		f = os.Stdin
	} else {
		f, err = os.Open(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
		if err != nil {
			log.Fatal(err)
		}
	}

	data, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}

	return string(data)
}
