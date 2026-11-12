package vex

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/kev"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
)

const productID = "pkg:oci/ledger-gateway@sha256:deadbeef"

var fixedTime = time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

func exampleFindings(t *testing.T) []scan.Finding {
	t.Helper()
	res, err := scan.Load(filepath.Join("..", "..", "examples", "scan.grype.json"))
	if err != nil {
		t.Fatalf("load scan: %v", err)
	}
	return res.Findings
}

func exampleTriage(t *testing.T) *Triage {
	t.Helper()
	tr, err := LoadTriage(filepath.Join("..", "..", "examples", "triage.yaml"))
	if err != nil {
		t.Fatalf("load triage: %v", err)
	}
	return tr
}

func generate(t *testing.T, findings []scan.Finding, tr *Triage) (*Document, []string) {
	t.Helper()
	doc, warnings, err := Generate(findings, tr, Options{
		ProductID: productID,
		Author:    "Acme Software GmbH",
		Role:      "Manufacturer",
		Timestamp: fixedTime,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return doc, warnings
}

func TestGenerateFromExample(t *testing.T) {
	doc, warnings := generate(t, exampleFindings(t), exampleTriage(t))

	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none: every triage entry matches a finding", warnings)
	}
	if doc.Context != Context {
		t.Errorf("@context = %q, want %q", doc.Context, Context)
	}
	if len(doc.Statements) != 5 {
		t.Fatalf("statements = %d, want one per finding (5)", len(doc.Statements))
	}
	counts := doc.CountByStatus()
	if counts[StatusNotAffected] != 3 {
		t.Errorf("not_affected = %d, want 3", counts[StatusNotAffected])
	}
	if counts[StatusAffected] != 1 {
		t.Errorf("affected = %d, want 1", counts[StatusAffected])
	}
	if counts[StatusUnderInvestigation] != 1 {
		t.Errorf("under_investigation = %d, want 1", counts[StatusUnderInvestigation])
	}
}

func TestUntriagedFindingsBecomeUnderInvestigation(t *testing.T) {
	doc, _ := generate(t, exampleFindings(t), exampleTriage(t))
	status, ok := doc.StatusOf("CVE-2023-44487")
	if !ok {
		t.Fatal("CVE-2023-44487 has no statement; every finding must be represented")
	}
	if status != StatusUnderInvestigation {
		t.Errorf("CVE-2023-44487 = %s, want under_investigation — the tool must never decide not_affected on its own", status)
	}
}

func TestStatementsCarryProductAndSubcomponents(t *testing.T) {
	doc, _ := generate(t, exampleFindings(t), exampleTriage(t))
	for _, st := range doc.Statements {
		if len(st.Products) != 1 || st.Products[0].ID != productID {
			t.Fatalf("%s: products = %+v, want the product identifier", st.Vulnerability.Name, st.Products)
		}
		if len(st.Products[0].Subcomponents) == 0 {
			t.Errorf("%s: no subcomponents recorded", st.Vulnerability.Name)
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	first, _ := generate(t, exampleFindings(t), exampleTriage(t))
	second, _ := generate(t, exampleFindings(t), exampleTriage(t))

	a, err := first.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, err := second.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Error("two runs over identical inputs produced different documents")
	}
	if first.ID != second.ID {
		t.Errorf("@id differs between runs: %q vs %q", first.ID, second.ID)
	}
	if !strings.HasPrefix(first.ID, "https://openvex.dev/docs/public/vex-") {
		t.Errorf("@id = %q, want an openvex.dev document URI", first.ID)
	}
}

func TestGenerateIDChangesWithContent(t *testing.T) {
	findings := exampleFindings(t)
	base, _ := generate(t, findings, exampleTriage(t))
	fewer, _ := generate(t, findings[:2], exampleTriage(t))
	if base.ID == fewer.ID {
		t.Error("@id did not change when the statements changed")
	}
}

func TestTriageProductFilterScopesTheDecision(t *testing.T) {
	findings := []scan.Finding{
		{ID: "CVE-1", Severity: "High", Name: "a", Version: "1", PURL: "pkg:npm/a@1"},
		{ID: "CVE-1", Severity: "High", Name: "b", Version: "1", PURL: "pkg:npm/b@1"},
	}
	tr := &Triage{Statements: []TriageEntry{{
		Vulnerability: "CVE-1",
		Products:      []string{"pkg:npm/a@1"},
		Status:        StatusNotAffected,
		Justification: "component_not_present",
	}}}
	doc, warnings := generate(t, findings, tr)

	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2 (one per decision)", len(doc.Statements))
	}
	var statuses []Status
	for _, st := range doc.Statements {
		statuses = append(statuses, st.Status)
	}
	if statuses[0] != StatusNotAffected || statuses[1] != StatusUnderInvestigation {
		t.Errorf("statuses = %v, want [not_affected under_investigation]", statuses)
	}
}

func TestUnmatchedTriageEntryWarns(t *testing.T) {
	tr := &Triage{Statements: []TriageEntry{{
		Vulnerability: "CVE-9999-0001",
		Status:        StatusFixed,
	}}}
	_, warnings := generate(t, exampleFindings(t), tr)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "CVE-9999-0001") {
		t.Errorf("warnings = %v, want one warning about the stale entry", warnings)
	}
}

func TestGenerateRequiresProductAndAuthor(t *testing.T) {
	if _, _, err := Generate(nil, nil, Options{Author: "a"}); err == nil {
		t.Error("Generate accepted a missing product identifier")
	}
	if _, _, err := Generate(nil, nil, Options{ProductID: "p"}); err == nil {
		t.Error("Generate accepted a missing author")
	}
}

func TestTriageValidation(t *testing.T) {
	cases := []struct {
		name  string
		entry TriageEntry
		want  string
	}{
		{
			name:  "not_affected without justification or impact",
			entry: TriageEntry{Vulnerability: "CVE-1", Status: StatusNotAffected},
			want:  "requires a justification",
		},
		{
			name:  "not_affected with an invented justification",
			entry: TriageEntry{Vulnerability: "CVE-1", Status: StatusNotAffected, Justification: "we_looked_at_it"},
			want:  "is not one of",
		},
		{
			name:  "affected without an action",
			entry: TriageEntry{Vulnerability: "CVE-1", Status: StatusAffected},
			want:  "requires an action statement",
		},
		{
			name:  "unknown status",
			entry: TriageEntry{Vulnerability: "CVE-1", Status: "probably_fine"},
			want:  "is not one of",
		},
		{
			name:  "missing vulnerability id",
			entry: TriageEntry{Status: StatusFixed},
			want:  "vulnerability is required",
		},
		{
			name:  "justification on a fixed statement",
			entry: TriageEntry{Vulnerability: "CVE-1", Status: StatusFixed, Justification: "component_not_present"},
			want:  "only valid with status not_affected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Triage{Statements: []TriageEntry{tc.entry}}
			err := tr.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestTriageValidAcceptsEveryStatus(t *testing.T) {
	tr := &Triage{Statements: []TriageEntry{
		{Vulnerability: "CVE-1", Status: StatusNotAffected, Justification: "component_not_present"},
		{Vulnerability: "CVE-2", Status: StatusNotAffected, Impact: "reachable only from the offline importer"},
		{Vulnerability: "CVE-3", Status: StatusAffected, Action: "patch in 4.7.0"},
		{Vulnerability: "CVE-4", Status: StatusFixed},
		{Vulnerability: "CVE-5", Status: StatusUnderInvestigation},
	}}
	if err := tr.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestParseTriageRejectsUnknownFields(t *testing.T) {
	_, err := ParseTriage([]byte("statements:\n  - vulnerability: CVE-1\n    stattus: fixed\n"))
	if err == nil {
		t.Fatal("ParseTriage accepted a misspelled field, want an error")
	}
}

func TestGenerateRejectsInvalidTriage(t *testing.T) {
	tr := &Triage{Statements: []TriageEntry{{Vulnerability: "CVE-1", Status: StatusAffected}}}
	if _, _, err := Generate(exampleFindings(t), tr, Options{ProductID: "p", Author: "a"}); err == nil {
		t.Fatal("Generate accepted an invalid triage file")
	}
}

func TestParseRoundTrip(t *testing.T) {
	doc, _ := generate(t, exampleFindings(t), exampleTriage(t))
	data, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(back.Statements) != len(doc.Statements) || back.ID != doc.ID {
		t.Error("round trip through JSON lost content")
	}
}

func exampleKEV(t *testing.T) *kev.Catalog {
	t.Helper()
	c, err := kev.Load(filepath.Join("..", "..", "examples", "kev.json"))
	if err != nil {
		t.Fatalf("load kev: %v", err)
	}
	return c
}

func TestKEVNoteMarksOnlyOpenStatements(t *testing.T) {
	doc, _, err := Generate(exampleFindings(t), exampleTriage(t), Options{
		ProductID: productID,
		Author:    "Acme Software GmbH",
		Timestamp: fixedTime,
		KEV:       exampleKEV(t),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, st := range doc.Statements {
		switch st.Vulnerability.Name {
		case "CVE-2023-44487": // KEV-listed and under_investigation
			if !strings.Contains(st.StatusNotes, "since 2023-10-10 (catalog 2026.11.10)") ||
				!strings.Contains(st.StatusNotes, "Article 14") {
				t.Errorf("CVE-2023-44487 status_notes = %q, want the KEV marker", st.StatusNotes)
			}
		case "CVE-2021-44228": // KEV-listed but triaged not_affected
			if st.StatusNotes != "" {
				t.Errorf("not_affected statement carries status_notes %q", st.StatusNotes)
			}
		default:
			if st.StatusNotes != "" {
				t.Errorf("%s is not KEV-listed but carries status_notes %q", st.Vulnerability.Name, st.StatusNotes)
			}
		}
	}
	if n := doc.KEVListed(); n != 1 {
		t.Errorf("KEVListed = %d, want 1", n)
	}
}

func TestKEVNoteOnAffectedStatement(t *testing.T) {
	tr := &Triage{Statements: []TriageEntry{
		{Vulnerability: "CVE-2021-44228", Status: StatusAffected, Action: "Upgrade log4j-core to 2.17.1."},
	}}
	doc, _, err := Generate(exampleFindings(t), tr, Options{
		ProductID: productID, Author: "Acme Software GmbH", Timestamp: fixedTime, KEV: exampleKEV(t),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, st := range doc.Statements {
		if st.Vulnerability.Name == "CVE-2021-44228" && !strings.Contains(st.StatusNotes, "since 2021-12-10") {
			t.Errorf("affected KEV statement status_notes = %q", st.StatusNotes)
		}
	}
}

func TestStatusNotesRoundTrip(t *testing.T) {
	doc, _, err := Generate(exampleFindings(t), exampleTriage(t), Options{
		ProductID: productID, Author: "Acme Software GmbH", Timestamp: fixedTime, KEV: exampleKEV(t),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"status_notes": "KEV: `) {
		t.Error("status_notes is not serialised under its OpenVEX name")
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if back.KEVListed() != 1 {
		t.Errorf("KEVListed after round trip = %d, want 1", back.KEVListed())
	}
}

func TestNoKEVCatalogLeavesNotesEmpty(t *testing.T) {
	doc, _ := generate(t, exampleFindings(t), exampleTriage(t))
	if doc.KEVListed() != 0 {
		t.Error("statements were KEV-marked without a catalog")
	}
}
