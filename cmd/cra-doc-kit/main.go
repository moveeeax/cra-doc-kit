// Command cra-doc-kit turns the artefacts a build already produces — a
// CycloneDX SBOM and a vulnerability scan — into the paperwork the EU Cyber
// Resilience Act asks for.
package main

import (
	"os"

	"github.com/moveeeax/cra-doc-kit/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
