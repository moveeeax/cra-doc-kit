// Package kev reads the CISA Known Exploited Vulnerabilities catalog.
//
// The catalog is read from a local copy of the JSON feed, so the binary still
// makes no network calls. Keeping that copy current is the caller's job; the
// catalog version is carried into every report so a stale copy is visible.
package kev

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/moveeeax/cra-doc-kit/internal/scan"
)

// Entry is one catalog entry. Only the fields the reports use are decoded.
type Entry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
	RansomwareUse     string `json:"knownRansomwareCampaignUse"`
}

// Catalog is a parsed KEV feed, indexed by CVE ID.
type Catalog struct {
	Version  string // catalogVersion, e.g. 2026.11.10
	Released string // dateReleased
	entries  map[string]Entry
}

type feed struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

// Load reads and parses a KEV JSON feed from disk.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read kev: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse decodes a KEV JSON feed.
func Parse(data []byte) (*Catalog, error) {
	var f feed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse kev: %w", err)
	}
	if f.Vulnerabilities == nil || f.CatalogVersion == "" {
		return nil, fmt.Errorf("parse kev: no catalogVersion or \"vulnerabilities\" array; is this the CISA KEV JSON feed?")
	}
	c := &Catalog{Version: f.CatalogVersion, Released: f.DateReleased, entries: map[string]Entry{}}
	for _, e := range f.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(e.CVEID))
		if id == "" {
			continue
		}
		e.CVEID = id
		c.entries[id] = e
	}
	return c, nil
}

// Len returns the number of entries in the catalog.
func (c *Catalog) Len() int { return len(c.entries) }

// Lookup returns the catalog entry for a finding. The finding's own ID is
// tried first, then the aliases the scanner reported, so a GHSA match still
// resolves to the CVE that CISA lists.
func (c *Catalog) Lookup(f scan.Finding) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	for _, id := range append([]string{f.ID}, f.Aliases...) {
		if e, ok := c.entries[strings.ToUpper(id)]; ok {
			return e, true
		}
	}
	return Entry{}, false
}
