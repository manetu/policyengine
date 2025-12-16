//
//  Copyright © Manetu Inc. All rights reserved.
//

package mock

import "regexp"

func convertSelectors(selectors []interface{}) []string {
	result := []string{}
	for _, s := range selectors {
		result = append(result, s.(string))
	}
	return result
}

func matchSelectors(op string, selectors []string) bool {
	for _, selector := range selectors {
		matched, err := regexp.MatchString(selector, op)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func toStringArray(coll []interface{}) []string {
	s := make([]string, len(coll))
	for i, item := range coll {
		s[i] = item.(string)
	}
	return s
}
