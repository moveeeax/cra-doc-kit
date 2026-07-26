// Package vex renders OpenVEX v0.2.0 documents from a scan plus human triage.
//
// There is deliberately no automatic triage or reachability analysis here: a
// finding with no human decision is emitted as under_investigation, never as
// not_affected. Guessing "not affected" on a client's behalf is the one thing
// that would turn this deliverable into a liability.
package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/scan"
)

// Context is the OpenVEX context URI this package emits.
const Context = "https://openvex.dev/ns/v0.2.0"

// Status is an OpenVEX statement status label.
type Status string

// The four OpenVEX statuses.
const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Statuses lists every valid status, in reporting order.
var Statuses = []Status{StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation}

// Justifications lists the five machine-readable not_affected justifications
// defined by OpenVEX. Free text is not accepted here on purpose.
var Justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Document is an OpenVEX document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX statement.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Timestamp       string        `json:"timestamp,omitempty"`
	Products        []Product     `json:"products"`
	Status          Status        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Vulnerability identifies the vulnerability a statement is about.
type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Product is the product a statement applies to, plus the components inside it
// that carry the vulnerable code.
type Product struct {
	ID            string      `json:"@id"`
	Subcomponents []Component `json:"subcomponents,omitempty"`
}

// Component is a subcomponent reference.
type Component struct {
	ID string `json:"@id"`
}

// Options controls document generation.
type Options struct {
	ProductID string    // purl or other identifier of the product under assessment
	Author    string    // who is making these statements
	Role      string    // e.g. "Manufacturer"
	Tooling   string    // tool identifier written into the document
	Timestamp time.Time // document timestamp; zero means time.Now().UTC()
}

// Generate builds an OpenVEX document from scan findings and a triage file.
// Findings with no matching triage entry become under_investigation.
// Warnings describe triage entries that matched nothing.
func Generate(findings []scan.Finding, triage *Triage, opts Options) (*Document, []string, error) {
	if opts.ProductID == "" {
		return nil, nil, fmt.Errorf("product identifier is required (use --product or set product.purl in the profile)")
	}
	if opts.Author == "" {
		return nil, nil, fmt.Errorf("author is required (use --author or set manufacturer.legal_name in the profile)")
	}
	if triage == nil {
		triage = &Triage{}
	}
	if err := triage.Validate(); err != nil {
		return nil, nil, err
	}

	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	stamp := ts.UTC().Format(time.RFC3339)

	type groupKey struct {
		vuln   string
		status Status
		just   string
		impact string
		action string
		descr  string
	}
	groups := map[groupKey]map[string]bool{}
	used := make([]bool, len(triage.Statements))

	for _, f := range findings {
		key := groupKey{vuln: f.ID, status: StatusUnderInvestigation, descr: f.Description}
		if idx, entry := triage.match(f); entry != nil {
			used[idx] = true
			key = groupKey{
				vuln:   f.ID,
				status: entry.Status,
				just:   entry.Justification,
				impact: entry.Impact,
				action: entry.Action,
				descr:  f.Description,
			}
		}
		sub := f.PURL
		if sub == "" {
			sub = f.Name + "@" + f.Version
		}
		if groups[key] == nil {
			groups[key] = map[string]bool{}
		}
		groups[key][sub] = true
	}

	var warnings []string
	for i, st := range triage.Statements {
		if !used[i] {
			warnings = append(warnings, fmt.Sprintf("triage entry %d (%s) matched no finding in the scan", i+1, st.Vulnerability))
		}
	}

	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].vuln != keys[j].vuln {
			return keys[i].vuln < keys[j].vuln
		}
		return keys[i].status < keys[j].status
	})

	doc := &Document{
		Context:   Context,
		Author:    opts.Author,
		Role:      opts.Role,
		Timestamp: stamp,
		Version:   1,
		Tooling:   opts.Tooling,
	}
	for _, k := range keys {
		subs := make([]Component, 0, len(groups[k]))
		for s := range groups[k] {
			subs = append(subs, Component{ID: s})
		}
		sort.Slice(subs, func(i, j int) bool { return subs[i].ID < subs[j].ID })
		doc.Statements = append(doc.Statements, Statement{
			Vulnerability:   Vulnerability{Name: k.vuln, Description: k.descr},
			Timestamp:       stamp,
			Products:        []Product{{ID: opts.ProductID, Subcomponents: subs}},
			Status:          k.status,
			Justification:   k.just,
			ImpactStatement: k.impact,
			ActionStatement: k.action,
		})
	}
	doc.ID = doc.canonicalID()
	return doc, warnings, nil
}

// canonicalID derives a stable @id from the statement content, so re-running
// the tool on unchanged inputs produces a byte-identical document and CI diffs
// stay meaningful.
func (d *Document) canonicalID() string {
	payload, err := json.Marshal(struct {
		Author     string      `json:"author"`
		Timestamp  string      `json:"timestamp"`
		Statements []Statement `json:"statements"`
	}{d.Author, d.Timestamp, d.Statements})
	if err != nil {
		payload = []byte(d.Author + d.Timestamp)
	}
	sum := sha256.Sum256(payload)
	return "https://openvex.dev/docs/public/vex-" + hex.EncodeToString(sum[:])
}

// Marshal renders the document as indented JSON with a trailing newline.
func (d *Document) Marshal() ([]byte, error) {
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Parse decodes an OpenVEX document.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse vex: %w", err)
	}
	if len(doc.Statements) == 0 && doc.Context == "" {
		return nil, fmt.Errorf("parse vex: no @context and no statements; is this an OpenVEX document?")
	}
	return &doc, nil
}

// CountByStatus returns the number of statements per status.
func (d *Document) CountByStatus() map[Status]int {
	out := map[Status]int{}
	for _, s := range d.Statements {
		out[s.Status]++
	}
	return out
}

// StatusOf returns the status asserted for a vulnerability ID, if any.
func (d *Document) StatusOf(vulnID string) (Status, bool) {
	for _, s := range d.Statements {
		if s.Vulnerability.Name == vulnID {
			return s.Status, true
		}
	}
	return "", false
}
