// Package textfmt holds the small grammar helpers the reports need. A client
// deliverable that says "1 findings are" reads as machine output; these keep it
// reading as a document.
package textfmt

import "fmt"

// Count renders a number with the right noun form: Count(1, "finding",
// "findings") is "1 finding".
func Count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Have returns "has" for one item and "have" otherwise.
func Have(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

// Is returns "is" for one item and "are" otherwise.
func Is(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
