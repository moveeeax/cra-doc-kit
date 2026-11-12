package gapcheck

import (
	"encoding/json"
	"fmt"
	"strings"
)

var severityLabel = map[Severity]string{
	Blocker: "BLOCKER",
	Warning: "WARNING",
	Info:    "INFO",
	Pass:    "PASS",
}

// Markdown renders the report as the Gap Check deliverable body.
func (r *Report) Markdown() string {
	var b strings.Builder

	product := r.Product
	if product == "" {
		product = "(product not named in SBOM)"
	}
	fmt.Fprintf(&b, "# CRA Gap Check — %s\n\n", product)
	fmt.Fprintf(&b, "Generated: %s by cra-doc-kit\n\n", r.Generated)

	fmt.Fprintf(&b, "| Input | File |\n|---|---|\n")
	fmt.Fprintf(&b, "| SBOM | `%s` |\n", orDash(r.SBOM))
	fmt.Fprintf(&b, "| Vulnerability scan | `%s` |\n", orDash(r.Scan))
	fmt.Fprintf(&b, "| VEX | `%s` |\n", orDash(r.VEX))
	fmt.Fprintf(&b, "| CISA KEV catalog | `%s` |\n\n", orDash(r.KEV))

	fmt.Fprintf(&b, "**Result: %d blocker(s), %d warning(s), %d note(s), %d passed check(s) across %d components.**\n\n",
		r.Counts.Blocker, r.Counts.Warning, r.Counts.Info, r.Counts.Pass, r.Components)

	b.WriteString("## Summary\n\n")
	b.WriteString("| Check | Result | CRA reference |\n|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s %s | %s | %s |\n", f.Rule, escapePipes(f.Title), severityLabel[f.Severity], f.Reference)
	}
	b.WriteString("\n")

	for _, sev := range []Severity{Blocker, Warning, Info} {
		var group []Finding
		for _, f := range r.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n", sectionTitle(sev))
		for _, f := range group {
			fmt.Fprintf(&b, "### %s — %s\n\n", f.Rule, f.Title)
			fmt.Fprintf(&b, "*Reference: %s*\n\n", f.Reference)
			fmt.Fprintf(&b, "%s\n\n", f.Detail)
			if len(f.Evidence) > 0 {
				for _, e := range f.Evidence {
					fmt.Fprintf(&b, "- `%s`\n", e)
				}
				b.WriteString("\n")
			}
		}
	}

	b.WriteString("## Scope of this check\n\n")
	b.WriteString("This report is a machine-generated readiness check over an SBOM, a vulnerability scan and a VEX document. ")
	b.WriteString("It does not assess the essential requirements of Annex I Part I that depend on the product's design, ")
	b.WriteString("and it is not a conformity assessment. The author of this report is not a notified body and issues no ")
	b.WriteString("Declaration of Conformity.\n")
	return b.String()
}

// JSON renders the report as indented JSON with a trailing newline.
func (r *Report) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func sectionTitle(s Severity) string {
	switch s {
	case Blocker:
		return "Blockers"
	case Warning:
		return "Warnings"
	default:
		return "Notes"
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
