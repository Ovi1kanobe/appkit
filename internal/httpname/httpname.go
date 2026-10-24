// Package httpname checks HTTP names, for the AppKit packages that read a
// header name from configuration or a route's options.
package httpname

import "strings"

// ValidHeaderName reports whether name is a non-empty HTTP header name: only
// letters, digits, and the token punctuation RFC 9110 allows.
func ValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		isLetterOrDigit := character < 128 && (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
		if !isLetterOrDigit && !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}
