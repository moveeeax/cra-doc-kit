// Package sbom reads the subset of CycloneDX needed for CRA paperwork.
//
// It is deliberately not a full CycloneDX implementation: it models the fields
// that Annex I Part II(1) and an Annex VII technical file actually depend on
// (component identity, supplier, licence, hashes, dependency graph) and ignores
// the rest so that a slightly non-conformant SBOM from a real build pipeline
// still parses instead of failing the whole delivery.
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Document is a CycloneDX BOM.
type Document struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     *Metadata    `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// Metadata is the BOM-level metadata block.
type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     Tools      `json:"tools"`
	Authors   []Contact  `json:"authors"`
	Supplier  *Entity    `json:"supplier"`
	Component *Component `json:"component"`
}

// Component is a single SBOM entry.
type Component struct {
	BOMRef      string      `json:"bom-ref"`
	Type        string      `json:"type"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Group       string      `json:"group"`
	PURL        string      `json:"purl"`
	Description string      `json:"description"`
	Author      string      `json:"author"`
	Publisher   string      `json:"publisher"`
	Supplier    *Entity     `json:"supplier"`
	Licenses    []License   `json:"licenses"`
	Hashes      []Hash      `json:"hashes"`
	Components  []Component `json:"components"`
}

// Entity is a CycloneDX organizationalEntity.
type Entity struct {
	Name string    `json:"name"`
	URL  []string  `json:"url"`
	Cont []Contact `json:"contact"`
}

// Contact is a CycloneDX organizationalContact.
type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Hash is a CycloneDX hash entry.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// License is a CycloneDX licenseChoice: either a licence object or an expression.
type License struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

// Dependency is one node of the CycloneDX dependency graph.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Tools absorbs both the CycloneDX <=1.4 array form and the 1.5+ object form.
type Tools struct {
	Names []string
}

// UnmarshalJSON accepts `"tools": [...]` and `"tools": {"components": [...]}`.
func (t *Tools) UnmarshalJSON(data []byte) error {
	type toolEntry struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor"`
		Version string `json:"version"`
	}
	add := func(entries []toolEntry) {
		for _, e := range entries {
			if e.Name == "" {
				continue
			}
			name := e.Name
			if e.Version != "" {
				name += " " + e.Version
			}
			t.Names = append(t.Names, name)
		}
	}

	var asArray []toolEntry
	if err := json.Unmarshal(data, &asArray); err == nil {
		add(asArray)
		return nil
	}

	var asObject struct {
		Components []toolEntry `json:"components"`
		Services   []toolEntry `json:"services"`
	}
	if err := json.Unmarshal(data, &asObject); err != nil {
		return fmt.Errorf("metadata.tools: unrecognised shape: %w", err)
	}
	add(asObject.Components)
	add(asObject.Services)
	return nil
}

// Load reads and parses a CycloneDX JSON document from disk.
func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sbom: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// Parse decodes a CycloneDX JSON document.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse sbom: %w", err)
	}
	if !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return nil, fmt.Errorf("parse sbom: bomFormat is %q, only CycloneDX is supported", doc.BOMFormat)
	}
	return &doc, nil
}

// Flatten returns every component in the document, including nested ones,
// sorted by purl (falling back to name@version) so output is deterministic.
func (d *Document) Flatten() []Component {
	var out []Component
	var walk func([]Component)
	walk = func(cs []Component) {
		for _, c := range cs {
			nested := c.Components
			c.Components = nil
			out = append(out, c)
			walk(nested)
		}
	}
	walk(d.Components)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Key is a stable identifier for a component.
func (c Component) Key() string {
	if c.PURL != "" {
		return c.PURL
	}
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// Ecosystem returns the purl type of a component ("npm", "golang", "maven"),
// or "unknown" when there is no usable purl.
func (c Component) Ecosystem() string {
	return PURLType(c.PURL)
}

// PURLType extracts the type segment of a package URL.
func PURLType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "unknown"
	}
	typ, _, ok := strings.Cut(rest, "/")
	if !ok || typ == "" {
		return "unknown"
	}
	return strings.ToLower(typ)
}

// LicenseNames returns the licence identifiers or expressions declared for a component.
func (c Component) LicenseNames() []string {
	var out []string
	for _, l := range c.Licenses {
		switch {
		case l.Expression != "":
			out = append(out, l.Expression)
		case l.License != nil && l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License != nil && l.License.Name != "":
			out = append(out, l.License.Name)
		}
	}
	return out
}

// SupplierName returns the best available "who published this" string.
func (c Component) SupplierName() string {
	if c.Supplier != nil && c.Supplier.Name != "" {
		return c.Supplier.Name
	}
	if c.Author != "" {
		return c.Author
	}
	return c.Publisher
}

// Product returns the component the SBOM describes (metadata.component).
func (d *Document) Product() *Component {
	if d.Metadata == nil {
		return nil
	}
	return d.Metadata.Component
}

// DirectDependencies returns the refs the product component depends on. CRA
// Annex I Part II(1) requires "at the very least the top-level dependencies",
// so knowing whether this is empty is a compliance fact, not a nicety.
func (d *Document) DirectDependencies() []string {
	product := d.Product()
	if product == nil || product.BOMRef == "" {
		return nil
	}
	for _, dep := range d.Dependencies {
		if dep.Ref == product.BOMRef {
			out := append([]string(nil), dep.DependsOn...)
			sort.Strings(out)
			return out
		}
	}
	return nil
}

// EcosystemCount is one row of the ecosystem breakdown.
type EcosystemCount struct {
	Ecosystem string
	Count     int
}

// Ecosystems counts components per purl type, most common first.
func (d *Document) Ecosystems() []EcosystemCount {
	counts := map[string]int{}
	for _, c := range d.Flatten() {
		counts[c.Ecosystem()]++
	}
	out := make([]EcosystemCount, 0, len(counts))
	for eco, n := range counts {
		out = append(out, EcosystemCount{Ecosystem: eco, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out
}

// SupportedEcosystems are the package types this kit has been exercised
// against. Everything else is reported but not claimed as covered.
var SupportedEcosystems = []string{"golang", "maven", "npm"}

// IsSupportedEcosystem reports whether an ecosystem is in SupportedEcosystems.
func IsSupportedEcosystem(eco string) bool {
	for _, s := range SupportedEcosystems {
		if s == eco {
			return true
		}
	}
	return false
}
