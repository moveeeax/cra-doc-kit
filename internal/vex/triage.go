package vex

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/moveeeax/cra-doc-kit/internal/scan"
)

// Triage is the human decision file that drives VEX generation.
type Triage struct {
	Author     string        `yaml:"author"`
	Role       string        `yaml:"role"`
	Statements []TriageEntry `yaml:"statements"`
}

// TriageEntry is one analyst decision about one vulnerability.
type TriageEntry struct {
	Vulnerability string   `yaml:"vulnerability"`
	Products      []string `yaml:"products"` // optional purl filter; empty means every affected component
	Status        Status   `yaml:"status"`
	Justification string   `yaml:"justification"`
	Impact        string   `yaml:"impact"`
	Action        string   `yaml:"action"`
}

// LoadTriage reads a triage YAML file.
func LoadTriage(path string) (*Triage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read triage: %w", err)
	}
	t, err := ParseTriage(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// ParseTriage decodes triage YAML.
func ParseTriage(data []byte) (*Triage, error) {
	var t Triage
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse triage: %w", err)
	}
	return &t, nil
}

// Validate checks every entry against the OpenVEX rules for required fields.
func (t *Triage) Validate() error {
	var problems []string
	for i, s := range t.Statements {
		where := fmt.Sprintf("statement %d", i+1)
		if s.Vulnerability != "" {
			where = fmt.Sprintf("statement %d (%s)", i+1, s.Vulnerability)
		}
		if s.Vulnerability == "" {
			problems = append(problems, where+": vulnerability is required")
		}
		if !validStatus(s.Status) {
			problems = append(problems, fmt.Sprintf("%s: status %q is not one of %s", where, s.Status, joinStatuses()))
			continue
		}
		switch s.Status {
		case StatusNotAffected:
			if s.Justification == "" && s.Impact == "" {
				problems = append(problems, where+": not_affected requires a justification or an impact statement")
			}
			if s.Justification != "" && !validJustification(s.Justification) {
				problems = append(problems, fmt.Sprintf("%s: justification %q is not one of %s",
					where, s.Justification, strings.Join(Justifications, ", ")))
			}
		case StatusAffected:
			if s.Action == "" {
				problems = append(problems, where+": affected requires an action statement")
			}
		default:
			if s.Justification != "" {
				problems = append(problems, fmt.Sprintf("%s: justification is only valid with status not_affected", where))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("triage file is not valid:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// match returns the first triage entry that applies to a finding.
func (t *Triage) match(f scan.Finding) (int, *TriageEntry) {
	for i := range t.Statements {
		s := &t.Statements[i]
		if !strings.EqualFold(s.Vulnerability, f.ID) {
			continue
		}
		if len(s.Products) == 0 {
			return i, s
		}
		for _, p := range s.Products {
			if p == f.PURL || p == f.Name || p == f.Name+"@"+f.Version {
				return i, s
			}
		}
	}
	return -1, nil
}

func validStatus(s Status) bool {
	for _, v := range Statuses {
		if v == s {
			return true
		}
	}
	return false
}

func validJustification(j string) bool {
	for _, v := range Justifications {
		if v == j {
			return true
		}
	}
	return false
}

func joinStatuses() string {
	out := make([]string, 0, len(Statuses))
	for _, s := range Statuses {
		out = append(out, string(s))
	}
	return strings.Join(out, ", ")
}
