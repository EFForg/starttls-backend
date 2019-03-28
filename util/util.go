package util

import (
	"reflect"
)

// ListsEqual checks that two lists have the same elements,
// regardless of order.
func ListsEqual(x []string, y []string) bool {
	// Transform each list into a histogram
	xMap := make(map[string]uint)
	yMap := make(map[string]uint)
	for _, element := range x {
		if _, ok := xMap[element]; !ok {
			xMap[element] = 0
		}
		xMap[element]++
	}
	for _, element := range y {
		if _, ok := yMap[element]; !ok {
			yMap[element] = 0
		}
		yMap[element]++
	}
	// Compare the histogram maps
	return reflect.DeepEqual(xMap, yMap)
}
