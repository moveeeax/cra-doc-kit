// Package profile models the hand-written product facts that no tool can
// derive from an SBOM: who the manufacturer is, what the product is for, how
// long it is supported, and where the disclosure policy lives.
package profile

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Profile is the product profile YAML.
type Profile struct {
	Product      Product      `yaml:"product"`
	Manufacturer Manufacturer `yaml:"manufacturer"`
	Processes    Processes    `yaml:"processes"`
	Risk         Risk         `yaml:"risk"`
	Standards    []string     `yaml:"standards"`
	Tests        []Test       `yaml:"tests"`
	Conformity   Conformity   `yaml:"conformity"`
}

// Product describes the product with digital elements. Annex VII(1).
type Product struct {
	Name            string `yaml:"name"`
	Version         string `yaml:"version"`
	PURL            string `yaml:"purl"`
	IntendedPurpose string `yaml:"intended_purpose"`
	Description     string `yaml:"description"`
	// Category is the CRA classification the manufacturer has concluded:
	// "default", "important-class-i", "important-class-ii" or "critical".
	Category         string `yaml:"category"`
	SupportPeriodEnd string `yaml:"support_period_end"`
	UserDocs         string `yaml:"user_documentation"`
}

// Manufacturer is the economic operator placing the product on the market.
type Manufacturer struct {
	LegalName    string `yaml:"legal_name"`
	Address      string `yaml:"address"`
	Website      string `yaml:"website"`
	ContactEmail string `yaml:"contact_email"`
	// SecurityContact is the address published for vulnerability reports,
	// required by Annex I Part II(6).
	SecurityContact string `yaml:"security_contact"`
}

// Processes describes design, development, production and vulnerability
// handling. Annex VII(2).
type Processes struct {
	DesignAndDevelopment  string `yaml:"design_and_development"`
	Production            string `yaml:"production"`
	VulnerabilityHandling string `yaml:"vulnerability_handling"`
	SecurityUpdatePolicy  string `yaml:"security_update_policy"`
	CVDPolicyURL          string `yaml:"cvd_policy_url"`
	SBOMPublication       string `yaml:"sbom_publication"`
	// ReportingRunbook points at the 24-hour Article 14 reporting runbook.
	ReportingRunbook string `yaml:"reporting_runbook"`
}

// Risk is the cybersecurity risk assessment summary. Annex VII(3).
type Risk struct {
	Summary        string   `yaml:"summary"`
	Assets         []string `yaml:"assets"`
	Threats        []string `yaml:"threats"`
	Mitigations    []string `yaml:"mitigations"`
	AssessmentDate string   `yaml:"assessment_date"`
}

// Test is one verification activity. Annex VII(6).
type Test struct {
	Name   string `yaml:"name"`
	Date   string `yaml:"date"`
	Scope  string `yaml:"scope"`
	Result string `yaml:"result"`
	Report string `yaml:"report"`
}

// Conformity holds the pointers to the declaration and the assessment route.
// The kit never asserts conformity itself.
type Conformity struct {
	Procedure          string `yaml:"procedure"`
	DeclarationOfConf  string `yaml:"declaration_of_conformity"`
	NotifiedBody       string `yaml:"notified_body"`
	HarmonisedApproach string `yaml:"harmonised_approach"`
}

// Load reads a product profile YAML file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse decodes a product profile.
func Parse(data []byte) (*Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	return &p, nil
}

// Validate reports the fields without which the technical file cannot even be
// started. Everything else is allowed to be missing and is rendered as a TODO.
func (p *Profile) Validate() error {
	required := []struct{ key, value string }{
		{"product.name", p.Product.Name},
		{"product.version", p.Product.Version},
		{"manufacturer.legal_name", p.Manufacturer.LegalName},
		{"manufacturer.address", p.Manufacturer.Address},
		{"manufacturer.contact_email", p.Manufacturer.ContactEmail},
	}
	var missing []string
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			missing = append(missing, r.key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("profile is missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// CategoryLabel renders the CRA product category in the wording used by the
// regulation, or a TODO when the manufacturer has not concluded one.
func (p *Profile) CategoryLabel() string {
	switch strings.ToLower(strings.TrimSpace(p.Product.Category)) {
	case "default":
		return "Default category (Article 32(1)) — no Annex III or IV listing claimed"
	case "important-class-i":
		return "Important product, class I (Annex III, class I)"
	case "important-class-ii":
		return "Important product, class II (Annex III, class II)"
	case "critical":
		return "Critical product (Annex IV)"
	case "":
		return ""
	default:
		return p.Product.Category
	}
}
