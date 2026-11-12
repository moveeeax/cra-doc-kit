package annex

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/kev"
	"github.com/moveeeax/cra-doc-kit/internal/profile"
	"github.com/moveeeax/cra-doc-kit/internal/sbom"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
	"github.com/moveeeax/cra-doc-kit/internal/vex"
)

var fixedTime = time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

func ex(name string) string { return filepath.Join("..", "..", "examples", name) }

func example(t *testing.T) Input {
	t.Helper()
	p, err := profile.Load(ex("product.yaml"))
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	doc, err := sbom.Load(ex("sbom.cdx.json"))
	if err != nil {
		t.Fatalf("load sbom: %v", err)
	}
	res, err := scan.Load(ex("scan.grype.json"))
	if err != nil {
		t.Fatalf("load scan: %v", err)
	}
	tr, err := vex.LoadTriage(ex("triage.yaml"))
	if err != nil {
		t.Fatalf("load triage: %v", err)
	}
	vexDoc, _, err := vex.Generate(res.Findings, tr, vex.Options{
		ProductID: p.Product.PURL,
		Author:    p.Manufacturer.LegalName,
		Timestamp: fixedTime,
	})
	if err != nil {
		t.Fatalf("generate vex: %v", err)
	}
	return Input{
		Profile: p,
		SBOM:    doc, SBOMPath: "examples/sbom.cdx.json",
		Scan: res, ScanPath: "examples/scan.grype.json",
		VEX: vexDoc, VEXPath: "examples/vex.json",
		Now: fixedTime,
	}
}

func render(t *testing.T, in Input) (string, *View) {
	t.Helper()
	out, view, err := Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out, view
}

func TestRenderFillsWhatItKnows(t *testing.T) {
	out, _ := render(t, example(t))

	for _, want := range []string{
		"**Product:** Acme Ledger Gateway 4.6.2",
		"**Manufacturer:** Acme Software GmbH",
		"Important product, class I (Annex III, class I)",
		"| Format | CycloneDX 1.5 |",
		"| Components | 9 |",
		"| Declared direct dependencies | 4 |",
		"| npm | 3 |",
		"Scanner: grype 0.87.0",
		"| `not_affected` | 3 |",
		"| Part II(1) |",
		"CycloneDX 1.5, 9 components, 4 direct dependencies (examples/sbom.cdx.json).",
		"24 hours from becoming aware",
		"not a notified body",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered file is missing %q", want)
		}
	}
}

func TestRenderMarksMissingFactsAsTODO(t *testing.T) {
	out, view := render(t, example(t))

	wantTODOs := []string{
		"conformity.declaration_of_conformity",
		"processes.production",
		"processes.reporting_runbook",
		"product.user_documentation",
		"standards",
	}
	if len(view.TODOs) != len(wantTODOs) {
		t.Fatalf("TODOs = %v, want %v", view.TODOs, wantTODOs)
	}
	for i, want := range wantTODOs {
		if view.TODOs[i] != want {
			t.Errorf("TODO %d = %q, want %q", i, view.TODOs[i], want)
		}
	}
	if !strings.Contains(out, "**TODO — set `product.user_documentation` in the product profile.**") {
		t.Error("the missing user documentation is not visible in the body")
	}
	if !strings.Contains(out, "5 profile fields are still empty") {
		t.Error("the open items summary does not count the TODOs")
	}
}

func TestRenderNeverInventsProse(t *testing.T) {
	in := example(t)
	in.Profile.Processes.VulnerabilityHandling = ""
	out, view := render(t, in)

	if !strings.Contains(out, "**TODO — set `processes.vulnerability_handling` in the product profile.**") {
		t.Error("an emptied field was not rendered as a TODO")
	}
	for _, r := range view.PartII {
		if r.Ref == "Part II(2)" {
			if r.Status != statusOpen {
				t.Errorf("Part II(2) status = %q, want %q", r.Status, statusOpen)
			}
			if !strings.Contains(r.Evidence, "processes.vulnerability_handling") {
				t.Errorf("Part II(2) evidence = %q, want it to name the missing key", r.Evidence)
			}
		}
	}
}

func TestPartOneKnownVulnerabilitiesReflectsTriage(t *testing.T) {
	in := example(t)
	_, view := render(t, in)

	var got Requirement
	for _, r := range view.PartI {
		if r.Ref == "Part I(2)(a)" {
			got = r
		}
	}
	if got.Status != statusOpen {
		t.Errorf("Part I(2)(a) status = %q, want %q while findings are open", got.Status, statusOpen)
	}
	if !strings.Contains(got.Evidence, "2 of 5 findings") {
		t.Errorf("Part I(2)(a) evidence = %q", got.Evidence)
	}

	// Close every open statement and the requirement becomes documented.
	for i := range in.VEX.Statements {
		in.VEX.Statements[i].Status = vex.StatusNotAffected
	}
	_, view = render(t, in)
	for _, r := range view.PartI {
		if r.Ref == "Part I(2)(a)" && r.Status != statusDocumented {
			t.Errorf("Part I(2)(a) status = %q after full triage, want %q", r.Status, statusDocumented)
		}
	}
}

func TestRenderWithoutScanOrVEX(t *testing.T) {
	in := example(t)
	in.Scan, in.ScanPath, in.VEX, in.VEXPath = nil, "", nil, ""
	out, _ := render(t, in)

	if !strings.Contains(out, "**TODO — no vulnerability scan supplied.") {
		t.Error("a missing scan is not flagged in section 2.4")
	}
	if strings.Contains(out, "| VEX status |") {
		t.Error("a VEX table was rendered without a VEX document")
	}
}

func TestRenderRequiresACompleteProfile(t *testing.T) {
	in := example(t)
	in.Profile.Manufacturer.Address = ""
	if _, _, err := Render(in); err == nil {
		t.Fatal("Render accepted a profile with no manufacturer address")
	} else if !strings.Contains(err.Error(), "manufacturer.address") {
		t.Errorf("error = %v, want it to name the missing field", err)
	}
}

func TestRenderRequiresProfileAndSBOM(t *testing.T) {
	if _, _, err := Render(Input{}); err == nil {
		t.Error("Render accepted an empty input")
	}
	in := example(t)
	in.SBOM = nil
	if _, _, err := Render(in); err == nil {
		t.Error("Render accepted a missing SBOM")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := render(t, example(t))
	b, _ := render(t, example(t))
	if a != b {
		t.Error("two renders of identical inputs differ")
	}
}

func TestSingularGrammar(t *testing.T) {
	_, view := render(t, example(t))
	for _, r := range view.PartII {
		if r.Ref == "Part II(3)" && r.Evidence != "1 test activity listed in section 6." {
			t.Errorf("Part II(3) evidence = %q, want the singular form", r.Evidence)
		}
	}
}

func TestCategoryLabels(t *testing.T) {
	cases := map[string]string{
		"default":            "Default category (Article 32(1)) — no Annex III or IV listing claimed",
		"important-class-i":  "Important product, class I (Annex III, class I)",
		"important-class-ii": "Important product, class II (Annex III, class II)",
		"critical":           "Critical product (Annex IV)",
		"":                   "",
		"something else":     "something else",
	}
	for in, want := range cases {
		p := &profile.Profile{}
		p.Product.Category = in
		if got := p.CategoryLabel(); got != want {
			t.Errorf("CategoryLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKEVTableListsCatalogMatches(t *testing.T) {
	in := example(t)
	c, err := kev.Load(ex("kev.json"))
	if err != nil {
		t.Fatalf("load kev: %v", err)
	}
	in.KEV, in.KEVPath = c, "examples/kev.json"
	out, view := render(t, in)

	if len(view.KEVRows) != 2 {
		t.Fatalf("KEV rows = %d, want 2 (CVE-2021-44228 and CVE-2023-44487)", len(view.KEVRows))
	}
	for _, want := range []string{
		"CISA KEV catalog 2026.11.10 (`examples/kev.json`)",
		"| CVE-2021-44228 | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` | Critical | `not_affected` | 2021-12-10 |",
		"| CVE-2023-44487 | `pkg:golang/golang.org/x/net@v0.15.0` | High | `under_investigation` | 2023-10-10 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered file is missing %q", want)
		}
	}
}

func TestKEVTableWithoutMatches(t *testing.T) {
	in := example(t)
	c, err := kev.Parse([]byte(`{"catalogVersion": "2026.01.01", "vulnerabilities": []}`))
	if err != nil {
		t.Fatalf("parse kev: %v", err)
	}
	in.KEV = c
	out, _ := render(t, in)
	if !strings.Contains(out, "No finding of the scan is listed in the catalog.") {
		t.Error("an empty KEV match is not stated")
	}
}

func TestNoKEVSectionWithoutCatalog(t *testing.T) {
	out, _ := render(t, example(t))
	if strings.Contains(out, "Known exploited vulnerabilities") {
		t.Error("a KEV section was rendered without a catalog")
	}
}
