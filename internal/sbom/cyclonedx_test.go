package sbom

import (
	"path/filepath"
	"testing"
)

func loadExample(t *testing.T) *Document {
	t.Helper()
	doc, err := Load(filepath.Join("..", "..", "examples", "sbom.cdx.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return doc
}

func TestLoadExample(t *testing.T) {
	doc := loadExample(t)

	if doc.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want 1.5", doc.SpecVersion)
	}
	if got := len(doc.Flatten()); got != 9 {
		t.Errorf("component count = %d, want 9", got)
	}
	p := doc.Product()
	if p == nil {
		t.Fatal("Product() = nil, want the ledger-gateway component")
	}
	if p.Name != "ledger-gateway" || p.Version != "4.6.2" {
		t.Errorf("product = %s %s, want ledger-gateway 4.6.2", p.Name, p.Version)
	}
	if got := len(doc.Metadata.Tools.Names); got != 1 || doc.Metadata.Tools.Names[0] != "syft 1.18.1" {
		t.Errorf("tools = %v, want [syft 1.18.1]", doc.Metadata.Tools.Names)
	}
}

func TestFlattenIsSorted(t *testing.T) {
	doc := loadExample(t)
	components := doc.Flatten()
	for i := 1; i < len(components); i++ {
		if components[i-1].Key() > components[i].Key() {
			t.Fatalf("components are not sorted: %q before %q", components[i-1].Key(), components[i].Key())
		}
	}
}

func TestFlattenIncludesNested(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "components": [
	    {"name": "outer", "version": "1.0.0", "purl": "pkg:npm/outer@1.0.0",
	     "components": [{"name": "inner", "version": "2.0.0", "purl": "pkg:npm/inner@2.0.0"}]}
	  ]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := doc.Flatten()
	if len(got) != 2 {
		t.Fatalf("Flatten() returned %d components, want 2 (nested must be included)", len(got))
	}
	if got[0].Name != "inner" || got[1].Name != "outer" {
		t.Errorf("Flatten() = %s, %s; want inner, outer", got[0].Name, got[1].Name)
	}
}

func TestDirectDependencies(t *testing.T) {
	doc := loadExample(t)
	direct := doc.DirectDependencies()
	if len(direct) != 4 {
		t.Fatalf("DirectDependencies() = %d entries, want 4: %v", len(direct), direct)
	}
	want := "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
	found := false
	for _, d := range direct {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Errorf("DirectDependencies() = %v, want it to contain %q", direct, want)
	}
}

func TestDirectDependenciesEmptyWithoutGraph(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.5",
	  "metadata": {"component": {"bom-ref": "p", "name": "p", "version": "1"}},
	  "components": [{"name": "a", "version": "1", "purl": "pkg:npm/a@1"}]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := doc.DirectDependencies(); len(got) != 0 {
		t.Errorf("DirectDependencies() = %v, want none when no dependency graph is present", got)
	}
}

func TestEcosystems(t *testing.T) {
	doc := loadExample(t)
	want := map[string]int{"npm": 3, "golang": 2, "maven": 2, "pypi": 1, "unknown": 1}
	got := map[string]int{}
	for _, e := range doc.Ecosystems() {
		got[e.Ecosystem] = e.Count
	}
	for eco, n := range want {
		if got[eco] != n {
			t.Errorf("ecosystem %s = %d, want %d", eco, got[eco], n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("ecosystems = %v, want exactly %v", got, want)
	}
}

func TestPURLType(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/axios@1.5.0":                         "npm",
		"pkg:golang/golang.org/x/net@v0.15.0":         "golang",
		"pkg:maven/org.apache.logging.log4j/x@2.14.1": "maven",
		"pkg:oci/img@sha256:abc?repository_url=r/x":   "oci",
		"":           "unknown",
		"not-a-purl": "unknown",
		"pkg:":       "unknown",
	}
	for in, want := range cases {
		if got := PURLType(in); got != want {
			t.Errorf("PURLType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLicenseNamesHandlesBothForms(t *testing.T) {
	doc := loadExample(t)
	byName := map[string][]string{}
	for _, c := range doc.Flatten() {
		byName[c.Name] = c.LicenseNames()
	}
	if got := byName["axios"]; len(got) != 1 || got[0] != "MIT" {
		t.Errorf("axios licences = %v, want [MIT] from the license.id form", got)
	}
	if got := byName["jackson-databind"]; len(got) != 1 || got[0] != "Apache-2.0" {
		t.Errorf("jackson-databind licences = %v, want [Apache-2.0] from the expression form", got)
	}
	if got := byName["left-pad"]; len(got) != 0 {
		t.Errorf("left-pad licences = %v, want none", got)
	}
}

func TestSupplierNameFallsBackToAuthor(t *testing.T) {
	c := Component{Author: "The Go Authors"}
	if got := c.SupplierName(); got != "The Go Authors" {
		t.Errorf("SupplierName() = %q, want the author", got)
	}
	c = Component{Supplier: &Entity{Name: "FasterXML"}, Author: "ignored"}
	if got := c.SupplierName(); got != "FasterXML" {
		t.Errorf("SupplierName() = %q, want the supplier to win", got)
	}
	if got := (Component{}).SupplierName(); got != "" {
		t.Errorf("SupplierName() = %q, want empty", got)
	}
}

func TestToolsAcceptsLegacyArray(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.4",
	  "metadata": {"tools": [{"vendor": "anchore", "name": "syft", "version": "0.98.0"}]},
	  "components": []
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := doc.Metadata.Tools.Names
	if len(got) != 1 || got[0] != "syft 0.98.0" {
		t.Errorf("tools = %v, want [syft 0.98.0] from the CycloneDX 1.4 array form", got)
	}
}

func TestParseRejectsForeignFormat(t *testing.T) {
	_, err := Parse([]byte(`{"spdxVersion": "SPDX-2.3", "name": "x"}`))
	if err == nil {
		t.Fatal("Parse accepted an SPDX document, want an error naming CycloneDX")
	}
}

func TestIsSupportedEcosystem(t *testing.T) {
	for _, eco := range []string{"npm", "golang", "maven"} {
		if !IsSupportedEcosystem(eco) {
			t.Errorf("IsSupportedEcosystem(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{"pypi", "unknown", "oci"} {
		if IsSupportedEcosystem(eco) {
			t.Errorf("IsSupportedEcosystem(%q) = true, want false", eco)
		}
	}
}
