package profile

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	p, err := Load(filepath.Join("..", "..", "examples", "product.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Product.Name != "Acme Ledger Gateway" || p.Product.Version != "4.6.2" {
		t.Errorf("product = %s %s", p.Product.Name, p.Product.Version)
	}
	if p.Manufacturer.SecurityContact != "security@example.com" {
		t.Errorf("security contact = %q", p.Manufacturer.SecurityContact)
	}
	if len(p.Risk.Threats) != 3 {
		t.Errorf("threats = %d, want 3", len(p.Risk.Threats))
	}
	if len(p.Tests) != 1 || p.Tests[0].Date != "2026-05-18" {
		t.Errorf("tests = %+v", p.Tests)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("the shipped example profile does not validate: %v", err)
	}
}

func TestValidateNamesEveryMissingField(t *testing.T) {
	err := (&Profile{}).Validate()
	if err == nil {
		t.Fatal("Validate() = nil for an empty profile")
	}
	for _, want := range []string{
		"product.name", "product.version",
		"manufacturer.legal_name", "manufacturer.address", "manufacturer.contact_email",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("product:\n  name: x\n  verison: 1.0\n"))
	if err == nil {
		t.Fatal("Parse accepted a misspelled key; a typo would silently drop a fact from the technical file")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join("does", "not", "exist.yaml")); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}
