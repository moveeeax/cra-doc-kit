package gapcheck

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/kev"
	"github.com/moveeeax/cra-doc-kit/internal/sbom"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
	"github.com/moveeeax/cra-doc-kit/internal/vex"
)

var fixedTime = time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

func example(t *testing.T) Input {
	t.Helper()
	doc, err := sbom.Load(filepath.Join("..", "..", "examples", "sbom.cdx.json"))
	if err != nil {
		t.Fatalf("load sbom: %v", err)
	}
	res, err := scan.Load(filepath.Join("..", "..", "examples", "scan.grype.json"))
	if err != nil {
		t.Fatalf("load scan: %v", err)
	}
	tr, err := vex.LoadTriage(filepath.Join("..", "..", "examples", "triage.yaml"))
	if err != nil {
		t.Fatalf("load triage: %v", err)
	}
	vexDoc, _, err := vex.Generate(res.Findings, tr, vex.Options{
		ProductID: "pkg:oci/ledger-gateway@sha256:deadbeef",
		Author:    "Acme Software GmbH",
		Timestamp: fixedTime,
	})
	if err != nil {
		t.Fatalf("generate vex: %v", err)
	}
	return Input{
		SBOM: doc, SBOMPath: "examples/sbom.cdx.json",
		Scan: res, ScanPath: "examples/scan.grype.json",
		VEX: vexDoc, VEXPath: "examples/vex.json",
		Now: fixedTime,
	}
}

func findingsByRule(r *Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		out[f.Rule] = f
	}
	return out
}

func TestRunOnExample(t *testing.T) {
	rep := Run(example(t))
	got := findingsByRule(rep)

	want := map[string]Severity{
		"SBOM-001": Pass,    // CycloneDX 1.5
		"SBOM-002": Pass,    // product named and versioned
		"SBOM-003": Pass,    // timestamp present
		"SBOM-004": Pass,    // syft recorded as the producer
		"SBOM-005": Pass,    // components present
		"SBOM-006": Pass,    // everything versioned
		"SBOM-007": Blocker, // the vendored internal library has no purl
		"SBOM-008": Warning, // left-pad has no supplier
		"SBOM-009": Warning, // two components declare no licence
		"SBOM-010": Info,    // only two components carry hashes
		"SBOM-011": Pass,    // dependency graph present
		"ECO-001":  Info,    // pypi is outside the supported set
		"VULN-001": Pass,    // scan supplied
		"VULN-002": Pass,    // every finding has a statement
		"VULN-003": Warning, // one finding is still under investigation
	}
	for rule, wantSev := range want {
		f, ok := got[rule]
		if !ok {
			t.Errorf("rule %s did not run", rule)
			continue
		}
		if f.Severity != wantSev {
			t.Errorf("%s = %s, want %s (detail: %s)", rule, f.Severity, wantSev, f.Detail)
		}
		if f.Reference == "" {
			t.Errorf("%s has no CRA reference", rule)
		}
	}
	if len(got) != len(want) {
		t.Errorf("report has %d rules, want %d", len(got), len(want))
	}
	if rep.Counts.Blocker != 1 || rep.Counts.Warning != 3 {
		t.Errorf("counts = %+v, want 1 blocker and 3 warnings", rep.Counts)
	}
	if rep.Product != "ledger-gateway 4.6.2" {
		t.Errorf("product = %q", rep.Product)
	}
}

func TestPURLBlockerNamesTheOffender(t *testing.T) {
	rep := Run(example(t))
	f := findingsByRule(rep)["SBOM-007"]
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "acme-crypto-helpers") {
		t.Errorf("SBOM-007 evidence = %v, want the vendored library named", f.Evidence)
	}
	if !strings.Contains(f.Detail, "1 of 9 components has no purl") {
		t.Errorf("SBOM-007 detail = %q, want a singular reading", f.Detail)
	}
}

func TestMissingScanIsABlocker(t *testing.T) {
	in := example(t)
	in.Scan, in.ScanPath, in.VEX, in.VEXPath = nil, "", nil, ""
	rep := Run(in)
	got := findingsByRule(rep)

	if got["VULN-001"].Severity != Blocker {
		t.Errorf("VULN-001 = %s, want blocker when no scan is supplied", got["VULN-001"].Severity)
	}
	if _, ok := got["VULN-003"]; ok {
		t.Error("VULN-003 ran without a VEX document")
	}
}

func TestMissingVEXIsAWarning(t *testing.T) {
	in := example(t)
	in.VEX, in.VEXPath = nil, ""
	got := findingsByRule(Run(in))
	if got["VULN-002"].Severity != Warning {
		t.Errorf("VULN-002 = %s, want warning when no VEX is supplied", got["VULN-002"].Severity)
	}
}

func TestUntriagedFindingsAreABlocker(t *testing.T) {
	in := example(t)
	// A VEX document that only covers one of the five findings.
	in.VEX = &vex.Document{Statements: []vex.Statement{{
		Vulnerability: vex.Vulnerability{Name: "CVE-2021-44228"},
		Status:        vex.StatusNotAffected,
	}}}
	f := findingsByRule(Run(in))["VULN-002"]
	if f.Severity != Blocker {
		t.Fatalf("VULN-002 = %s, want blocker", f.Severity)
	}
	if !strings.Contains(f.Detail, "4 of 5 findings have no VEX statement") {
		t.Errorf("VULN-002 detail = %q", f.Detail)
	}
}

func TestStaleVEXStatementsAreReported(t *testing.T) {
	in := example(t)
	in.VEX.Statements = append(in.VEX.Statements, vex.Statement{
		Vulnerability: vex.Vulnerability{Name: "CVE-2015-0001"},
		Status:        vex.StatusFixed,
	})
	f, ok := findingsByRule(Run(in))["VEX-001"]
	if !ok {
		t.Fatal("VEX-001 did not run")
	}
	if f.Severity != Info || len(f.Evidence) != 1 || f.Evidence[0] != "CVE-2015-0001" {
		t.Errorf("VEX-001 = %+v, want an info finding naming CVE-2015-0001", f)
	}
}

func TestBrokenSBOMProducesBlockers(t *testing.T) {
	doc, err := sbom.Parse([]byte(`{
	  "bomFormat": "CycloneDX",
	  "components": [{"name": "mystery"}]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := findingsByRule(Run(Input{SBOM: doc, Now: fixedTime}))

	for _, rule := range []string{"SBOM-001", "SBOM-002", "SBOM-006", "SBOM-007", "VULN-001"} {
		if got[rule].Severity != Blocker {
			t.Errorf("%s = %s, want blocker", rule, got[rule].Severity)
		}
	}
	if got["SBOM-003"].Severity != Warning {
		t.Errorf("SBOM-003 = %s, want warning", got["SBOM-003"].Severity)
	}
}

func TestExitCodeThresholds(t *testing.T) {
	rep := Run(example(t)) // 1 blocker, 3 warnings
	cases := []struct {
		failOn Severity
		want   int
	}{
		{Blocker, 1},
		{Warning, 1},
		{Info, 1},
		{"", 0},
	}
	for _, tc := range cases {
		if got := rep.ExitCode(tc.failOn); got != tc.want {
			t.Errorf("ExitCode(%q) = %d, want %d", tc.failOn, got, tc.want)
		}
	}

	clean := &Report{Counts: Counts{Pass: 12}}
	for _, failOn := range []Severity{Blocker, Warning, Info} {
		if got := clean.ExitCode(failOn); got != 0 {
			t.Errorf("clean report ExitCode(%q) = %d, want 0", failOn, got)
		}
	}

	warned := &Report{Counts: Counts{Warning: 1}}
	if warned.ExitCode(Blocker) != 0 {
		t.Error("a warning must not fail a --fail-on blocker run")
	}
	if warned.ExitCode(Warning) != 1 {
		t.Error("a warning must fail a --fail-on warning run")
	}
}

func TestMarkdownContainsTheBoundaryStatement(t *testing.T) {
	md := Run(example(t)).Markdown()
	for _, want := range []string{
		"# CRA Gap Check — ledger-gateway 4.6.2",
		"not a notified body",
		"| SBOM-007 Every component carries a package URL | BLOCKER |",
		"acme-crypto-helpers",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

func TestJSONIsValidAndComplete(t *testing.T) {
	data, err := Run(example(t)).JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("re-parsing the JSON report failed: %v", err)
	}
	if len(back.Findings) != 15 || back.Counts.Blocker != 1 {
		t.Errorf("round-tripped report = %d findings, %+v", len(back.Findings), back.Counts)
	}
	if back.Generated != "2026-07-20T10:00:00Z" {
		t.Errorf("generated = %q, want the supplied timestamp", back.Generated)
	}
}

func TestEvidenceIsTruncated(t *testing.T) {
	var components []sbom.Component
	for i := 0; i < 20; i++ {
		components = append(components, sbom.Component{Name: string(rune('a'+i)) + "-lib", Version: "1.0.0"})
	}
	f := ruleComponentPURLs(components, 3)
	if len(f.Evidence) != 4 {
		t.Fatalf("evidence = %d entries, want 3 plus an overflow line", len(f.Evidence))
	}
	if !strings.Contains(f.Evidence[3], "17 more") {
		t.Errorf("overflow line = %q, want it to count the remaining 17", f.Evidence[3])
	}
}

func withKEV(t *testing.T, in Input) Input {
	t.Helper()
	c, err := kev.Load(filepath.Join("..", "..", "examples", "kev.json"))
	if err != nil {
		t.Fatalf("load kev: %v", err)
	}
	in.KEV, in.KEVPath = c, "examples/kev.json"
	return in
}

func TestKEVRuleSkippedWithoutCatalog(t *testing.T) {
	if _, ok := findingsByRule(Run(example(t)))["VULN-004"]; ok {
		t.Error("VULN-004 ran without a KEV catalog")
	}
}

func TestKEVListedFindingUnderInvestigationIsABlocker(t *testing.T) {
	rep := Run(withKEV(t, example(t)))
	f := findingsByRule(rep)["VULN-004"]
	if f.Severity != Blocker {
		t.Fatalf("VULN-004 = %s, want blocker: CVE-2023-44487 is KEV-listed and under_investigation", f.Severity)
	}
	if !strings.Contains(f.Reference, "Article 14") {
		t.Errorf("VULN-004 reference = %q, want Article 14 cited", f.Reference)
	}
	// CVE-2021-44228 is KEV-listed too, but triaged not_affected.
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "CVE-2023-44487") ||
		!strings.Contains(f.Evidence[0], "KEV since 2023-10-10, under_investigation") {
		t.Errorf("VULN-004 evidence = %v, want only CVE-2023-44487 with its KEV date and status", f.Evidence)
	}
	if !strings.Contains(f.Detail, "1 of 2 findings listed in the CISA KEV catalog 2026.11.10 is not closed") {
		t.Errorf("VULN-004 detail = %q", f.Detail)
	}
	if rep.KEV != "examples/kev.json" {
		t.Errorf("report KEV path = %q", rep.KEV)
	}
}

func TestKEVListedFindingAffectedIsABlocker(t *testing.T) {
	in := withKEV(t, example(t))
	for i, st := range in.VEX.Statements {
		if st.Vulnerability.Name == "CVE-2021-44228" {
			in.VEX.Statements[i].Status = vex.StatusAffected
		}
		if st.Vulnerability.Name == "CVE-2023-44487" {
			in.VEX.Statements[i].Status = vex.StatusFixed
		}
	}
	f := findingsByRule(Run(in))["VULN-004"]
	if f.Severity != Blocker || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "CVE-2021-44228") {
		t.Errorf("VULN-004 = %+v, want a blocker naming the affected CVE-2021-44228", f)
	}
}

func TestKEVListedFindingWithoutVEXIsABlocker(t *testing.T) {
	in := withKEV(t, example(t))
	in.VEX, in.VEXPath = nil, ""
	f := findingsByRule(Run(in))["VULN-004"]
	if f.Severity != Blocker || len(f.Evidence) != 2 {
		t.Fatalf("VULN-004 = %+v, want a blocker naming both KEV-listed findings", f)
	}
	if !strings.Contains(f.Evidence[0], "no VEX statement") {
		t.Errorf("evidence = %v, want the missing decision named", f.Evidence)
	}
}

func TestKEVRulePassesWhenEveryListedFindingIsClosed(t *testing.T) {
	in := withKEV(t, example(t))
	for i, st := range in.VEX.Statements {
		if st.Vulnerability.Name == "CVE-2023-44487" {
			in.VEX.Statements[i].Status = vex.StatusNotAffected
		}
	}
	f := findingsByRule(Run(in))["VULN-004"]
	if f.Severity != Pass {
		t.Fatalf("VULN-004 = %s, want pass", f.Severity)
	}
	if !strings.Contains(f.Detail, "2 findings are listed") {
		t.Errorf("VULN-004 detail = %q", f.Detail)
	}
}

func TestKEVRulePassesWhenNothingIsListed(t *testing.T) {
	in := example(t)
	c, err := kev.Parse([]byte(`{"catalogVersion": "2026.01.01", "vulnerabilities": []}`))
	if err != nil {
		t.Fatalf("parse kev: %v", err)
	}
	in.KEV = c
	f := findingsByRule(Run(in))["VULN-004"]
	if f.Severity != Pass || !strings.Contains(f.Detail, "None of the 5 findings") {
		t.Errorf("VULN-004 = %+v, want a pass naming the finding count", f)
	}
}
