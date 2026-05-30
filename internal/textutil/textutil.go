package textutil

import "strings"

func DashIfEmpty(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func SingleLine(value string, limit int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	if limit > 0 && len(value) > limit {
		return value[:limit] + "..."
	}
	return value
}

func EscapeMarkdownPipes(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
