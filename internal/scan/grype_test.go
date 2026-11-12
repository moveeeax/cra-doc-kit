package scan

import (
	"path/filepath"
	"testing"
)

func loadExample(t *testing.T) *Result {
	t.Helper()
	res, err := Load(filepath.Join("..", "..", "examples", "scan.grype.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return res
}

func TestLoadExample(t *testing.T) {
	res := loadExample(t)
	if res.Scanner != "grype 0.87.0" {
		t.Errorf("scanner = %q, want grype 0.87.0", res.Scanner)
	}
	if len(res.Findings) != 5 {
		t.Fatalf("findings = %d, want 5", len(res.Findings))
	}
	first := res.Findings[0]
	if first.ID != "CVE-2021-44228" {
		t.Errorf("first finding = %s, want the Critical CVE-2021-44228 to sort first", first.ID)
	}
	if first.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("first finding purl = %q", first.PURL)
	}
	if !first.Fixed() || len(first.FixVersions) != 1 {
		t.Errorf("CVE-2021-44228 should report the 2.15.0 fix, got %v", first.FixVersions)
	}
}

func TestSortIsBySeverityThenID(t *testing.T) {
	res := loadExample(t)
	for i := 1; i < len(res.Findings); i++ {
		prev, cur := res.Findings[i-1], res.Findings[i]
		if SeverityRank(prev.Severity) > SeverityRank(cur.Severity) {
			t.Fatalf("findings out of order: %s (%s) before %s (%s)", prev.ID, prev.Severity, cur.ID, cur.Severity)
		}
		if SeverityRank(prev.Severity) == SeverityRank(cur.Severity) && prev.ID > cur.ID {
			t.Fatalf("equal severities not ordered by ID: %s before %s", prev.ID, cur.ID)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	res := loadExample(t)
	counts := res.CountBySeverity()
	want := map[string]int{"Critical": 1, "High": 3, "Medium": 1}
	for sev, n := range want {
		if counts[sev] != n {
			t.Errorf("%s = %d, want %d", sev, counts[sev], n)
		}
	}
}

func TestParseDeduplicates(t *testing.T) {
	res, err := Parse([]byte(`{"matches": [
	  {"vulnerability": {"id": "CVE-1", "severity": "high"}, "artifact": {"name": "a", "version": "1", "purl": "pkg:npm/a@1"}},
	  {"vulnerability": {"id": "CVE-1", "severity": "high"}, "artifact": {"name": "a", "version": "1", "purl": "pkg:npm/a@1"}},
	  {"vulnerability": {"id": "CVE-1", "severity": "high"}, "artifact": {"name": "b", "version": "1", "purl": "pkg:npm/b@1"}}
	]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 after deduplication", len(res.Findings))
	}
	if res.Findings[0].Severity != "High" {
		t.Errorf("severity = %q, want the normalised %q", res.Findings[0].Severity, "High")
	}
}

func TestParseRejectsNonGrypeJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"bomFormat": "CycloneDX"}`)); err == nil {
		t.Fatal("Parse accepted a CycloneDX document, want an error")
	}
}

func TestParseAcceptsEmptyMatches(t *testing.T) {
	res, err := Parse([]byte(`{"matches": [], "descriptor": {"name": "grype", "version": "1.0.0"}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(res.Findings))
	}
}

func TestFixedRequiresAVersionOrState(t *testing.T) {
	if (Finding{}).Fixed() {
		t.Error("empty finding reported as fixed")
	}
	if !(Finding{FixState: "fixed"}).Fixed() {
		t.Error("fix state 'fixed' not reported as fixed")
	}
	if (Finding{FixState: "wont-fix"}).Fixed() {
		t.Error("wont-fix reported as fixed")
	}
}

func TestSeverityRankUnknownSortsLast(t *testing.T) {
	if SeverityRank("Critical") >= SeverityRank("Low") {
		t.Error("Critical must rank before Low")
	}
	if SeverityRank("nonsense") <= SeverityRank("Negligible") {
		t.Error("an unrecognised severity must rank last")
	}
}

func TestParseKeepsRelatedVulnerabilitiesAsAliases(t *testing.T) {
	res, err := Parse([]byte(`{"matches": [
	  {"vulnerability": {"id": "GHSA-0000-0000-0001", "severity": "critical"},
	   "relatedVulnerabilities": [{"id": "CVE-2021-44228"}, {"id": "GHSA-0000-0000-0001"}],
	   "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}
	]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := res.Findings[0].Aliases
	if len(got) != 1 || got[0] != "CVE-2021-44228" {
		t.Errorf("aliases = %v, want [CVE-2021-44228] without the finding's own ID", got)
	}
}
