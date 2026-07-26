// Package annex renders the Annex VII technical file skeleton.
//
// The split is deliberate: sections that can be derived from an SBOM, a scan
// and a VEX document are filled with real data, and everything that depends on
// the manufacturer's own design decisions is emitted as an explicit TODO with
// the profile field that would fill it. A generated paragraph of plausible
// prose in a technical file is worse than a visible gap.
package annex

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/profile"
	"github.com/moveeeax/cra-doc-kit/internal/sbom"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
	"github.com/moveeeax/cra-doc-kit/internal/textfmt"
	"github.com/moveeeax/cra-doc-kit/internal/vex"
)

//go:embed annex7.md.tmpl
var annexTemplate string

// Input is everything the renderer can draw on. Scan and VEX may be nil.
type Input struct {
	Profile  *profile.Profile
	SBOM     *sbom.Document
	SBOMPath string
	Scan     *scan.Result
	ScanPath string
	VEX      *vex.Document
	VEXPath  string
	Now      time.Time
}

// View is the template data model.
type View struct {
	Generated string
	SBOMPath  string
	ScanPath  string
	VEXPath   string
	Scanner   string

	Product      profile.Product
	Manufacturer profile.Manufacturer
	Category     string

	Components  int
	DirectDeps  int
	SpecVersion string
	SBOMStamp   string
	Ecosystems  []sbom.EcosystemCount
	Licences    []LicenceCount

	Findings     int
	Severities   []SeverityCount
	VEXStatuses  []StatusCount
	OpenFindings int

	Standards []string
	Tests     []profile.Test
	Risk      profile.Risk

	PartI  []Requirement
	PartII []Requirement

	TODOs []string

	fields map[string]string
}

// LicenceCount is one row of the licence breakdown.
type LicenceCount struct {
	Licence string
	Count   int
}

// SeverityCount is one row of the vulnerability severity breakdown.
type SeverityCount struct {
	Severity string
	Count    int
}

// StatusCount is one row of the VEX status breakdown.
type StatusCount struct {
	Status string
	Count  int
}

// Requirement is one essential requirement row of the applicability table.
type Requirement struct {
	Ref      string
	Text     string
	Status   string
	Evidence string
}

// Field returns a profile-derived value, or a visible TODO marker naming the
// profile key that would fill it.
func (v *View) Field(key string) string {
	if val, ok := v.fields[key]; ok && strings.TrimSpace(val) != "" {
		return val
	}
	return fmt.Sprintf("**TODO — set `%s` in the product profile.**", key)
}

// Render produces the Annex VII skeleton as Markdown.
func Render(in Input) (string, *View, error) {
	if in.Profile == nil {
		return "", nil, fmt.Errorf("a product profile is required")
	}
	if err := in.Profile.Validate(); err != nil {
		return "", nil, err
	}
	if in.SBOM == nil {
		return "", nil, fmt.Errorf("an SBOM is required")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	v := buildView(in, now)

	tmpl, err := template.New("annex7").Parse(annexTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("parse annex template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", nil, fmt.Errorf("render annex: %w", err)
	}
	return buf.String(), v, nil
}

func buildView(in Input, now time.Time) *View {
	p := in.Profile
	components := in.SBOM.Flatten()

	v := &View{
		Generated:    now.UTC().Format(time.RFC3339),
		SBOMPath:     in.SBOMPath,
		ScanPath:     in.ScanPath,
		VEXPath:      in.VEXPath,
		Product:      p.Product,
		Manufacturer: p.Manufacturer,
		Category:     p.CategoryLabel(),
		Components:   len(components),
		DirectDeps:   len(in.SBOM.DirectDependencies()),
		SpecVersion:  in.SBOM.SpecVersion,
		Ecosystems:   in.SBOM.Ecosystems(),
		Licences:     licenceCounts(components),
		Standards:    p.Standards,
		Tests:        p.Tests,
		Risk:         p.Risk,
	}
	if in.SBOM.Metadata != nil {
		v.SBOMStamp = in.SBOM.Metadata.Timestamp
	}

	if in.Scan != nil {
		v.Scanner = in.Scan.Scanner
		v.Findings = len(in.Scan.Findings)
		counts := in.Scan.CountBySeverity()
		for _, s := range scan.SeverityOrder {
			if counts[s] > 0 {
				v.Severities = append(v.Severities, SeverityCount{Severity: s, Count: counts[s]})
			}
		}
	}
	if in.VEX != nil {
		counts := in.VEX.CountByStatus()
		for _, s := range vex.Statuses {
			if counts[s] > 0 {
				v.VEXStatuses = append(v.VEXStatuses, StatusCount{Status: string(s), Count: counts[s]})
			}
		}
		v.OpenFindings = counts[vex.StatusAffected] + counts[vex.StatusUnderInvestigation]
	}

	v.fields = map[string]string{
		"product.intended_purpose":             p.Product.IntendedPurpose,
		"product.description":                  p.Product.Description,
		"product.category":                     p.CategoryLabel(),
		"product.support_period_end":           p.Product.SupportPeriodEnd,
		"product.user_documentation":           p.Product.UserDocs,
		"manufacturer.security_contact":        p.Manufacturer.SecurityContact,
		"manufacturer.website":                 p.Manufacturer.Website,
		"processes.design_and_development":     p.Processes.DesignAndDevelopment,
		"processes.production":                 p.Processes.Production,
		"processes.vulnerability_handling":     p.Processes.VulnerabilityHandling,
		"processes.security_update_policy":     p.Processes.SecurityUpdatePolicy,
		"processes.cvd_policy_url":             p.Processes.CVDPolicyURL,
		"processes.sbom_publication":           p.Processes.SBOMPublication,
		"processes.reporting_runbook":          p.Processes.ReportingRunbook,
		"risk.summary":                         p.Risk.Summary,
		"risk.assessment_date":                 p.Risk.AssessmentDate,
		"conformity.procedure":                 p.Conformity.Procedure,
		"conformity.declaration_of_conformity": p.Conformity.DeclarationOfConf,
	}

	v.PartI = partOneRequirements(in, v)
	v.PartII = partTwoRequirements(in, v)
	v.TODOs = collectTODOs(v)
	return v
}

func collectTODOs(v *View) []string {
	var todos []string
	for key, val := range v.fields {
		if strings.TrimSpace(val) == "" {
			todos = append(todos, key)
		}
	}
	if len(v.Standards) == 0 {
		todos = append(todos, "standards")
	}
	if len(v.Tests) == 0 {
		todos = append(todos, "tests")
	}
	if strings.TrimSpace(v.Risk.Summary) == "" && len(v.Risk.Threats) == 0 {
		todos = append(todos, "risk.threats")
	}
	sort.Strings(todos)
	return todos
}

func licenceCounts(components []sbom.Component) []LicenceCount {
	counts := map[string]int{}
	for _, c := range components {
		names := c.LicenseNames()
		if len(names) == 0 {
			counts["(undeclared)"]++
			continue
		}
		for _, n := range names {
			counts[n]++
		}
	}
	out := make([]LicenceCount, 0, len(counts))
	for l, n := range counts {
		out = append(out, LicenceCount{Licence: l, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Licence < out[j].Licence
	})
	return out
}

const (
	statusDocumented = "Documented"
	statusOpen       = "Manufacturer input required"
)

func req(ref, text, status, evidence string) Requirement {
	return Requirement{Ref: ref, Text: text, Status: status, Evidence: evidence}
}

// partOneRequirements paraphrases Annex I Part I. Only requirements that this
// kit can evidence from machine-readable inputs are marked as documented.
func partOneRequirements(in Input, v *View) []Requirement {
	known := statusOpen
	evidence := "No vulnerability scan supplied."
	if in.Scan != nil {
		switch {
		case in.VEX == nil:
			evidence = fmt.Sprintf("%d findings from %s; no VEX document supplied.", v.Findings, v.Scanner)
		case v.OpenFindings == 0 && v.Findings > 0:
			known = statusDocumented
			evidence = fmt.Sprintf("%d findings, all VEX-triaged as not_affected or fixed (%s).", v.Findings, in.VEXPath)
		case v.Findings == 0:
			known = statusDocumented
			evidence = fmt.Sprintf("%s reported no findings.", v.Scanner)
		default:
			evidence = fmt.Sprintf("%d of %d findings are affected or still under investigation (%s).", v.OpenFindings, v.Findings, in.VEXPath)
		}
	}

	return []Requirement{
		req("Part I(1)", "Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks", statusOf(v, "processes.design_and_development"), evidenceOf(v, "processes.design_and_development", "Described in section 2.1.")),
		req("Part I(2)(a)", "Made available without known exploitable vulnerabilities", known, evidence),
		req("Part I(2)(b)", "Secure by default configuration, with reset to original state", statusOpen, ""),
		req("Part I(2)(c)", "Vulnerabilities can be addressed through security updates", statusOf(v, "processes.security_update_policy"), evidenceOf(v, "processes.security_update_policy", "Described in section 2.2.")),
		req("Part I(2)(d)", "Protection from unauthorised access through appropriate control mechanisms", statusOpen, ""),
		req("Part I(2)(e)", "Confidentiality of stored, transmitted or processed data", statusOpen, ""),
		req("Part I(2)(f)", "Integrity of data, commands, configuration and product state", statusOpen, ""),
		req("Part I(2)(g)", "Data minimisation", statusOpen, ""),
		req("Part I(2)(h)", "Availability of essential functions, including resilience against denial of service", statusOpen, ""),
		req("Part I(2)(i)", "Minimising negative impact on availability of other devices or networks", statusOpen, ""),
		req("Part I(2)(j)", "Limited attack surfaces, including external interfaces", statusOpen, ""),
		req("Part I(2)(k)", "Reduced impact of incidents through exploitation mitigation mechanisms", statusOpen, ""),
		req("Part I(2)(l)", "Security-relevant logging and monitoring, with an opt-out for the user", statusOpen, ""),
		req("Part I(2)(m)", "Secure and easy permanent deletion of data and settings", statusOpen, ""),
	}
}

// partTwoRequirements paraphrases Annex I Part II, the vulnerability handling
// requirements. This is the half the kit can genuinely evidence.
func partTwoRequirements(in Input, v *View) []Requirement {
	sbomStatus := statusDocumented
	sbomEvidence := fmt.Sprintf("CycloneDX %s, %d components, %d direct dependencies (%s).",
		v.SpecVersion, v.Components, v.DirectDeps, in.SBOMPath)
	if v.Components == 0 {
		sbomStatus = statusOpen
		sbomEvidence = "The SBOM lists no components."
	} else if v.DirectDeps == 0 {
		sbomEvidence += " No dependency graph: top-level dependencies are not distinguishable."
	}

	return []Requirement{
		req("Part II(1)", "Identify and document vulnerabilities and components, including an SBOM covering at least the top-level dependencies", sbomStatus, sbomEvidence),
		req("Part II(2)", "Address and remediate vulnerabilities without delay, with security updates separate from functionality updates", statusOf(v, "processes.vulnerability_handling"), evidenceOf(v, "processes.vulnerability_handling", "Described in section 2.2.")),
		req("Part II(3)", "Apply effective and regular tests and reviews of the security of the product", testStatus(v), testEvidence(v)),
		req("Part II(4)", "Publicly disclose information about fixed vulnerabilities once an update is available", statusOf(v, "processes.security_update_policy"), evidenceOf(v, "processes.security_update_policy", "Described in section 2.2.")),
		req("Part II(5)", "Put in place and enforce a coordinated vulnerability disclosure policy", statusOf(v, "processes.cvd_policy_url"), evidenceOf(v, "processes.cvd_policy_url", v.fields["processes.cvd_policy_url"])),
		req("Part II(6)", "Provide a contact address for reporting vulnerabilities, including in third-party components", statusOf(v, "manufacturer.security_contact"), evidenceOf(v, "manufacturer.security_contact", v.fields["manufacturer.security_contact"])),
		req("Part II(7)", "Provide mechanisms to securely distribute updates in a timely manner", statusOf(v, "processes.security_update_policy"), evidenceOf(v, "processes.security_update_policy", "Described in section 2.2.")),
		req("Part II(8)", "Disseminate security updates without delay and free of charge, with advisory messages", statusOf(v, "processes.security_update_policy"), evidenceOf(v, "processes.security_update_policy", "Described in section 2.2.")),
	}
}

func statusOf(v *View, key string) string {
	if strings.TrimSpace(v.fields[key]) != "" {
		return statusDocumented
	}
	return statusOpen
}

func evidenceOf(v *View, key, evidence string) string {
	if strings.TrimSpace(v.fields[key]) == "" {
		return fmt.Sprintf("TODO — `%s`", key)
	}
	return evidence
}

func testStatus(v *View) string {
	if len(v.Tests) > 0 {
		return statusDocumented
	}
	return statusOpen
}

func testEvidence(v *View) string {
	if len(v.Tests) == 0 {
		return "TODO — `tests`"
	}
	return fmt.Sprintf("%s listed in section 6.", textfmt.Count(len(v.Tests), "test activity", "test activities"))
}
