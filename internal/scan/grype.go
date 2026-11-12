// Package scan reads Grype JSON output and normalises it into findings.
//
// Only Grype's native JSON is supported on purpose: it is what the manual Gap
// Check is run with, and adding a second scanner format before a client has
// asked for one is speculative work.
package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Finding is one vulnerability match against one component.
type Finding struct {
	ID          string   // CVE-2024-1234, GHSA-xxxx, ...
	Severity    string   // Critical, High, Medium, Low, Negligible, Unknown
	PURL        string   // package URL of the affected component
	Name        string   // component name
	Version     string   // component version
	FixState    string   // fixed, not-fixed, wont-fix, unknown
	FixVersions []string // versions that resolve the finding
	DataSource  string   // advisory URL
	Description string
	Aliases     []string // related IDs Grype reports for the same issue, e.g. the CVE behind a GHSA
}

// Fixed reports whether an upgrade is available for this finding. A fixed
// finding that is neither remediated nor VEX-triaged is the hardest gap to
// defend in a technical file, so this drives a gapcheck rule.
func (f Finding) Fixed() bool {
	return len(f.FixVersions) > 0 || f.FixState == "fixed"
}

type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			DataSource  string `json:"dataSource"`
			Description string `json:"description"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

// Result is a parsed scan.
type Result struct {
	Scanner  string
	Findings []Finding
}

// Load reads and parses a Grype JSON report from disk.
func Load(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scan: %w", err)
	}
	res, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return res, nil
}

// Parse decodes a Grype JSON report.
func Parse(data []byte) (*Result, error) {
	var doc grypeDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse scan: %w", err)
	}
	if doc.Matches == nil {
		return nil, fmt.Errorf("parse scan: no \"matches\" array; is this Grype JSON output?")
	}

	scanner := doc.Descriptor.Name
	if scanner == "" {
		scanner = "grype"
	}
	if doc.Descriptor.Version != "" {
		scanner += " " + doc.Descriptor.Version
	}

	seen := map[string]bool{}
	res := &Result{Scanner: scanner}
	for _, m := range doc.Matches {
		f := Finding{
			ID:          m.Vulnerability.ID,
			Severity:    normaliseSeverity(m.Vulnerability.Severity),
			PURL:        m.Artifact.PURL,
			Name:        m.Artifact.Name,
			Version:     m.Artifact.Version,
			FixState:    m.Vulnerability.Fix.State,
			FixVersions: m.Vulnerability.Fix.Versions,
			DataSource:  m.Vulnerability.DataSource,
			Description: m.Vulnerability.Description,
		}
		if f.ID == "" {
			continue
		}
		for _, r := range m.RelatedVulnerabilities {
			if r.ID != "" && r.ID != f.ID {
				f.Aliases = append(f.Aliases, r.ID)
			}
		}
		key := f.ID + "|" + f.PURL
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Findings = append(res.Findings, f)
	}
	Sort(res.Findings)
	return res, nil
}

func normaliseSeverity(s string) string {
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

var severityRank = map[string]int{
	"Critical":   0,
	"High":       1,
	"Medium":     2,
	"Low":        3,
	"Negligible": 4,
	"Unknown":    5,
}

// SeverityRank orders severities most serious first.
func SeverityRank(s string) int {
	if r, ok := severityRank[normaliseSeverity(s)]; ok {
		return r
	}
	return len(severityRank)
}

// Sort orders findings by severity, then vulnerability ID, then component.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := SeverityRank(fs[i].Severity), SeverityRank(fs[j].Severity); ri != rj {
			return ri < rj
		}
		if fs[i].ID != fs[j].ID {
			return fs[i].ID < fs[j].ID
		}
		return fs[i].PURL < fs[j].PURL
	})
}

// CountBySeverity returns counts keyed by normalised severity.
func (r *Result) CountBySeverity() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// SeverityOrder is the canonical display order for severities.
var SeverityOrder = []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
