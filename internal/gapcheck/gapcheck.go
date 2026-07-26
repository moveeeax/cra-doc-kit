// Package gapcheck runs the automatable half of the CRA Gap Check over an
// SBOM, an optional vulnerability scan and an optional VEX document.
//
// Every rule states which part of Regulation (EU) 2024/2847 it maps to. The
// report is evidence for a human reviewer, not a conformity assessment: no
// rule here can be read as a claim that the product conforms.
package gapcheck

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/sbom"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
	"github.com/moveeeax/cra-doc-kit/internal/textfmt"
	"github.com/moveeeax/cra-doc-kit/internal/vex"
)

// Severity grades a finding.
type Severity string

// Finding severities, worst first.
const (
	Blocker Severity = "blocker"
	Warning Severity = "warning"
	Info    Severity = "info"
	Pass    Severity = "pass"
)

var severityRank = map[Severity]int{Blocker: 0, Warning: 1, Info: 2, Pass: 3}

// Finding is one rule outcome.
type Finding struct {
	Rule      string   `json:"rule"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Reference string   `json:"reference"`
	Detail    string   `json:"detail"`
	Evidence  []string `json:"evidence,omitempty"`
}

// Report is the full gap check outcome.
type Report struct {
	Product    string    `json:"product"`
	SBOM       string    `json:"sbom"`
	Scan       string    `json:"scan,omitempty"`
	VEX        string    `json:"vex,omitempty"`
	Generated  string    `json:"generated"`
	Findings   []Finding `json:"findings"`
	Counts     Counts    `json:"counts"`
	Components int       `json:"components"`
}

// Counts summarises findings by severity.
type Counts struct {
	Blocker int `json:"blocker"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
	Pass    int `json:"pass"`
}

// Input is everything the check can look at. Scan and VEX may be nil.
type Input struct {
	SBOM     *sbom.Document
	SBOMPath string
	Scan     *scan.Result
	ScanPath string
	VEX      *vex.Document
	VEXPath  string
	Now      time.Time
	// MaxEvidence caps how many offending components are listed per rule.
	MaxEvidence int
}

const defaultMaxEvidence = 8

// Run evaluates every rule against the input.
func Run(in Input) *Report {
	if in.MaxEvidence <= 0 {
		in.MaxEvidence = defaultMaxEvidence
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	rep := &Report{
		SBOM:      in.SBOMPath,
		Scan:      in.ScanPath,
		VEX:       in.VEXPath,
		Generated: now.UTC().Format(time.RFC3339),
	}
	if p := in.SBOM.Product(); p != nil {
		rep.Product = strings.TrimSpace(p.Name + " " + p.Version)
	}

	components := in.SBOM.Flatten()
	rep.Components = len(components)

	add := func(f Finding) { rep.Findings = append(rep.Findings, f) }

	add(ruleFormat(in.SBOM))
	add(ruleProductIdentity(in.SBOM))
	add(ruleTimestamp(in.SBOM))
	add(ruleAuthorship(in.SBOM))
	add(ruleComponentsPresent(components))
	add(ruleComponentVersions(components, in.MaxEvidence))
	add(ruleComponentPURLs(components, in.MaxEvidence))
	add(ruleSuppliers(components, in.MaxEvidence))
	add(ruleLicences(components, in.MaxEvidence))
	add(ruleHashes(components))
	add(ruleDependencyGraph(in.SBOM))
	add(ruleEcosystems(in.SBOM))
	rep.Findings = append(rep.Findings, vulnRules(in)...)

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		ri, rj := severityRank[rep.Findings[i].Severity], severityRank[rep.Findings[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return rep.Findings[i].Rule < rep.Findings[j].Rule
	})
	for _, f := range rep.Findings {
		switch f.Severity {
		case Blocker:
			rep.Counts.Blocker++
		case Warning:
			rep.Counts.Warning++
		case Info:
			rep.Counts.Info++
		case Pass:
			rep.Counts.Pass++
		}
	}
	return rep
}

// Worst returns the most serious severity present in the report.
func (r *Report) Worst() Severity {
	switch {
	case r.Counts.Blocker > 0:
		return Blocker
	case r.Counts.Warning > 0:
		return Warning
	case r.Counts.Info > 0:
		return Info
	default:
		return Pass
	}
}

// ExitCode maps the report against a --fail-on threshold.
func (r *Report) ExitCode(failOn Severity) int {
	if failOn == "" {
		return 0
	}
	if severityRank[r.Worst()] <= severityRank[failOn] {
		return 1
	}
	return 0
}

// --- individual rules -------------------------------------------------------

func ruleFormat(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "SBOM-001",
		Title:     "SBOM is in a commonly used machine-readable format",
		Reference: "Annex I Part II(1)",
	}
	spec := doc.SpecVersion
	if spec == "" {
		f.Severity = Blocker
		f.Detail = "CycloneDX document declares no specVersion."
		return f
	}
	if spec < "1.4" {
		f.Severity = Warning
		f.Detail = fmt.Sprintf("CycloneDX %s predates 1.4; VEX and licence expressions are poorly supported. Regenerate with a current Syft.", spec)
		return f
	}
	f.Severity = Pass
	f.Detail = fmt.Sprintf("CycloneDX %s.", spec)
	return f
}

func ruleProductIdentity(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "SBOM-002",
		Title:     "SBOM names the product it describes",
		Reference: "Annex VII(1)(a)-(b)",
	}
	p := doc.Product()
	switch {
	case p == nil || p.Name == "":
		f.Severity = Blocker
		f.Detail = "metadata.component is absent, so the SBOM does not say which product or version it belongs to. The technical file cannot reference it."
	case p.Version == "":
		f.Severity = Blocker
		f.Detail = fmt.Sprintf("metadata.component %q carries no version. Annex VII requires the versions affected by the documentation.", p.Name)
	default:
		f.Severity = Pass
		f.Detail = fmt.Sprintf("%s %s.", p.Name, p.Version)
	}
	return f
}

func ruleTimestamp(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "SBOM-003",
		Title:     "SBOM records when it was produced",
		Reference: "Annex I Part II(1)",
	}
	if doc.Metadata == nil || doc.Metadata.Timestamp == "" {
		f.Severity = Warning
		f.Detail = "metadata.timestamp is missing; there is no evidence the SBOM matches the released artefact."
		return f
	}
	if _, err := time.Parse(time.RFC3339, doc.Metadata.Timestamp); err != nil {
		f.Severity = Warning
		f.Detail = fmt.Sprintf("metadata.timestamp %q is not RFC 3339.", doc.Metadata.Timestamp)
		return f
	}
	f.Severity = Pass
	f.Detail = doc.Metadata.Timestamp
	return f
}

func ruleAuthorship(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "SBOM-004",
		Title:     "SBOM records who or what produced it",
		Reference: "Annex VII(2)(b)",
	}
	if doc.Metadata == nil {
		f.Severity = Warning
		f.Detail = "No metadata block at all."
		return f
	}
	var who []string
	who = append(who, doc.Metadata.Tools.Names...)
	for _, a := range doc.Metadata.Authors {
		if a.Name != "" {
			who = append(who, a.Name)
		}
	}
	if doc.Metadata.Supplier != nil && doc.Metadata.Supplier.Name != "" {
		who = append(who, doc.Metadata.Supplier.Name)
	}
	if len(who) == 0 {
		f.Severity = Warning
		f.Detail = "Neither metadata.tools, metadata.authors nor metadata.supplier is populated."
		return f
	}
	f.Severity = Pass
	f.Detail = strings.Join(who, ", ")
	return f
}

func ruleComponentsPresent(components []sbom.Component) Finding {
	f := Finding{
		Rule:      "SBOM-005",
		Title:     "SBOM lists components",
		Reference: "Annex I Part II(1)",
	}
	if len(components) == 0 {
		f.Severity = Blocker
		f.Detail = "The SBOM contains no components."
		return f
	}
	f.Severity = Pass
	f.Detail = textfmt.Count(len(components), "component", "components") + "."
	return f
}

func ruleComponentVersions(components []sbom.Component, max int) Finding {
	f := Finding{
		Rule:      "SBOM-006",
		Title:     "Every component carries a version",
		Reference: "Annex I Part II(1)",
	}
	var bad []string
	for _, c := range components {
		if c.Version == "" {
			bad = append(bad, c.Name)
		}
	}
	if len(bad) == 0 {
		f.Severity = Pass
		f.Detail = "All components are versioned."
		return f
	}
	f.Severity = Blocker
	f.Detail = fmt.Sprintf("%d of %d components %s no version; they cannot be matched against advisories.",
		len(bad), len(components), textfmt.Have(len(bad)))
	f.Evidence = truncate(bad, max)
	return f
}

func ruleComponentPURLs(components []sbom.Component, max int) Finding {
	f := Finding{
		Rule:      "SBOM-007",
		Title:     "Every component carries a package URL",
		Reference: "Annex I Part II(1)",
	}
	var bad []string
	for _, c := range components {
		if c.PURL == "" {
			bad = append(bad, c.Key())
		}
	}
	if len(bad) == 0 {
		f.Severity = Pass
		f.Detail = "All components carry a purl."
		return f
	}
	f.Severity = Blocker
	f.Detail = fmt.Sprintf("%d of %d components %s no purl; VEX statements cannot reference them unambiguously.",
		len(bad), len(components), textfmt.Have(len(bad)))
	f.Evidence = truncate(bad, max)
	return f
}

func ruleSuppliers(components []sbom.Component, max int) Finding {
	f := Finding{
		Rule:      "SBOM-008",
		Title:     "Components identify their supplier",
		Reference: "Annex VII(2)(b)",
	}
	var bad []string
	for _, c := range components {
		if c.SupplierName() == "" {
			bad = append(bad, c.Key())
		}
	}
	if len(bad) == 0 {
		f.Severity = Pass
		f.Detail = "All components name a supplier, author or publisher."
		return f
	}
	f.Severity = Warning
	f.Detail = fmt.Sprintf("%d of %d components name no supplier, author or publisher.", len(bad), len(components))
	f.Evidence = truncate(bad, max)
	return f
}

func ruleLicences(components []sbom.Component, max int) Finding {
	f := Finding{
		Rule:      "SBOM-009",
		Title:     "Components declare licence information",
		Reference: "Annex VII(2)(b)",
	}
	var bad []string
	for _, c := range components {
		if len(c.LicenseNames()) == 0 {
			bad = append(bad, c.Key())
		}
	}
	if len(bad) == 0 {
		f.Severity = Pass
		f.Detail = "All components declare a licence."
		return f
	}
	f.Severity = Warning
	f.Detail = fmt.Sprintf("%d of %d components declare no licence.", len(bad), len(components))
	f.Evidence = truncate(bad, max)
	return f
}

func ruleHashes(components []sbom.Component) Finding {
	f := Finding{
		Rule:      "SBOM-010",
		Title:     "Components carry integrity hashes",
		Reference: "Annex I Part I(2)(f)",
	}
	withHash := 0
	for _, c := range components {
		if len(c.Hashes) > 0 {
			withHash++
		}
	}
	switch {
	case len(components) == 0:
		f.Severity = Info
		f.Detail = "No components to hash."
	case withHash == len(components):
		f.Severity = Pass
		f.Detail = "All components carry at least one hash."
	default:
		f.Severity = Info
		f.Detail = fmt.Sprintf("%d of %d components carry a hash. Hashes are not required by the CRA but make the SBOM verifiable against the shipped artefact.", withHash, len(components))
	}
	return f
}

func ruleDependencyGraph(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "SBOM-011",
		Title:     "Top-level dependencies are identifiable",
		Reference: "Annex I Part II(1)",
	}
	direct := doc.DirectDependencies()
	if len(direct) == 0 {
		f.Severity = Warning
		f.Detail = "No dependency graph rooted at the product component. The CRA requires the SBOM to cover at the very least the top-level dependencies, and a flat list does not distinguish them from transitive ones."
		return f
	}
	f.Severity = Pass
	f.Detail = fmt.Sprintf("%d direct dependencies declared.", len(direct))
	return f
}

func ruleEcosystems(doc *sbom.Document) Finding {
	f := Finding{
		Rule:      "ECO-001",
		Title:     "Package ecosystems are within the tested coverage",
		Reference: "cra-doc-kit scope",
	}
	var parts, unsupported []string
	for _, e := range doc.Ecosystems() {
		parts = append(parts, fmt.Sprintf("%s: %d", e.Ecosystem, e.Count))
		if !sbom.IsSupportedEcosystem(e.Ecosystem) {
			unsupported = append(unsupported, e.Ecosystem)
		}
	}
	f.Detail = strings.Join(parts, ", ")
	if len(unsupported) == 0 {
		f.Severity = Pass
		return f
	}
	f.Severity = Info
	f.Evidence = unsupported
	f.Detail += fmt.Sprintf(". Ecosystems outside %s are reported but not covered by the fixed-price scope.",
		strings.Join(sbom.SupportedEcosystems, "/"))
	return f
}

func vulnRules(in Input) []Finding {
	if in.Scan == nil {
		return []Finding{{
			Rule:      "VULN-001",
			Title:     "Known vulnerabilities are enumerated",
			Severity:  Blocker,
			Reference: "Annex I Part I(2)(a)",
			Detail:    "No vulnerability scan was supplied. Article 13(1) and Annex I Part I(2)(a) require the product to be placed on the market without known exploitable vulnerabilities, which cannot be evidenced without a scan.",
		}}
	}

	var out []Finding
	counts := in.Scan.CountBySeverity()
	var parts []string
	for _, s := range scan.SeverityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", s, counts[s]))
		}
	}
	detail := "No findings."
	if len(parts) > 0 {
		detail = strings.Join(parts, ", ")
	}
	out = append(out, Finding{
		Rule:      "VULN-001",
		Title:     "Known vulnerabilities are enumerated",
		Severity:  Pass,
		Reference: "Annex I Part I(2)(a)",
		Detail:    fmt.Sprintf("%s scanned the product: %s", in.Scan.Scanner, detail),
	})

	// Findings that have a fix available and no VEX statement are the ones
	// that are hardest to defend in a technical file.
	var untriaged, underInvestigation []string
	for _, fnd := range in.Scan.Findings {
		status, has := vex.Status(""), false
		if in.VEX != nil {
			status, has = in.VEX.StatusOf(fnd.ID)
		}
		label := fmt.Sprintf("%s (%s) %s", fnd.ID, fnd.Severity, fnd.Name)
		switch {
		case !has && fnd.Fixed():
			untriaged = append(untriaged, label+" — fix available: "+strings.Join(fnd.FixVersions, ", "))
		case !has:
			untriaged = append(untriaged, label)
		case status == vex.StatusUnderInvestigation:
			underInvestigation = append(underInvestigation, label)
		}
	}

	triaged := Finding{
		Rule:      "VULN-002",
		Title:     "Every known vulnerability has a documented decision",
		Reference: "Annex I Part II(2)",
	}
	if in.VEX == nil {
		triaged.Severity = Warning
		triaged.Detail = "No VEX document was supplied, so no finding has a recorded decision. Run `cra-doc-kit vex` to produce one."
	} else if len(untriaged) == 0 {
		triaged.Severity = Pass
		triaged.Detail = fmt.Sprintf("All %s covered by a VEX statement.",
			textfmt.Count(len(in.Scan.Findings), "finding is", "findings are"))
	} else {
		triaged.Severity = Blocker
		triaged.Detail = fmt.Sprintf("%d of %d findings %s no VEX statement.",
			len(untriaged), len(in.Scan.Findings), textfmt.Have(len(untriaged)))
		triaged.Evidence = truncate(untriaged, in.MaxEvidence)
	}
	out = append(out, triaged)

	if in.VEX != nil {
		open := Finding{
			Rule:      "VULN-003",
			Title:     "No vulnerability is left under investigation at release",
			Reference: "Annex I Part II(2)",
		}
		if len(underInvestigation) == 0 {
			open.Severity = Pass
			open.Detail = "No statement is left at under_investigation."
		} else {
			open.Severity = Warning
			open.Detail = fmt.Sprintf("%s still under_investigation. That %s an honest state to ship, but it must be closed before the technical file is signed.",
				textfmt.Count(len(underInvestigation), "finding is", "findings are"), textfmt.Is(len(underInvestigation)))
			open.Evidence = truncate(underInvestigation, in.MaxEvidence)
		}
		out = append(out, open)

		// VEX statements about vulnerabilities the scan no longer reports.
		known := map[string]bool{}
		for _, fnd := range in.Scan.Findings {
			known[fnd.ID] = true
		}
		var stale []string
		for _, st := range in.VEX.Statements {
			if !known[st.Vulnerability.Name] {
				stale = append(stale, st.Vulnerability.Name)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			out = append(out, Finding{
				Rule:      "VEX-001",
				Title:     "VEX document matches the current scan",
				Severity:  Info,
				Reference: "Annex I Part II(4)",
				Detail: fmt.Sprintf("%s refer to vulnerabilities the current scan no longer reports. Keep them only if the affected version is still supported.",
					textfmt.Count(len(stale), "VEX statement", "VEX statements")),
				Evidence: truncate(stale, in.MaxEvidence),
			})
		}
	}
	return out
}

func truncate(items []string, max int) []string {
	sort.Strings(items)
	if len(items) <= max {
		return items
	}
	out := append([]string(nil), items[:max]...)
	return append(out, fmt.Sprintf("... and %d more", len(items)-max))
}
