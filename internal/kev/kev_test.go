package kev

import (
	"path/filepath"
	"testing"

	"github.com/moveeeax/cra-doc-kit/internal/scan"
)

func loadExample(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load(filepath.Join("..", "..", "examples", "kev.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestLoadExample(t *testing.T) {
	c := loadExample(t)
	if c.Version != "2026.11.10" {
		t.Errorf("version = %q, want 2026.11.10", c.Version)
	}
	if c.Len() != 2 {
		t.Fatalf("entries = %d, want 2", c.Len())
	}
	e, ok := c.Lookup(scan.Finding{ID: "CVE-2021-44228"})
	if !ok {
		t.Fatal("CVE-2021-44228 not found")
	}
	if e.DateAdded != "2021-12-10" || e.DueDate != "2021-12-24" {
		t.Errorf("dates = %s / %s, want 2021-12-10 / 2021-12-24", e.DateAdded, e.DueDate)
	}
}

func TestLookupFallsBackToAliases(t *testing.T) {
	c := loadExample(t)
	f := scan.Finding{ID: "GHSA-0000-0000-0002", Aliases: []string{"cve-2023-44487"}}
	e, ok := c.Lookup(f)
	if !ok || e.CVEID != "CVE-2023-44487" {
		t.Errorf("Lookup(%v) = %v, %v; want the CVE-2023-44487 entry via its alias", f, e, ok)
	}
	if _, ok := c.Lookup(scan.Finding{ID: "CVE-2020-8203"}); ok {
		t.Error("CVE-2020-8203 is not in the example catalog")
	}
}

func TestLookupOnNilCatalog(t *testing.T) {
	var c *Catalog
	if _, ok := c.Lookup(scan.Finding{ID: "CVE-2021-44228"}); ok {
		t.Error("a nil catalog matched a finding")
	}
}

func TestParseRejectsOtherJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"matches": []}`)); err == nil {
		t.Fatal("Parse accepted a Grype report, want an error")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("Parse accepted invalid JSON")
	}
}

func TestParseAcceptsEmptyCatalog(t *testing.T) {
	c, err := Parse([]byte(`{"catalogVersion": "2026.01.01", "dateReleased": "2026-01-01T00:00:00Z", "count": 0, "vulnerabilities": []}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Len() != 0 {
		t.Errorf("entries = %d, want 0", c.Len())
	}
}
