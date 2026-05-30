package scorecard

import (
	"strconv"
	"strings"
)

func formatScore(f float64) string {
	s := strings.TrimRight(strings.TrimRight(strconv.FormatFloat(f, 'f', 1, 64), "0"), ".")
	if s == "" {
		return "0"
	}
	return s
}
