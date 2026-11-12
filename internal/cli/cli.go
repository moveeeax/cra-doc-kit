// Package cli implements the cra-doc-kit command line.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moveeeax/cra-doc-kit/internal/annex"
	"github.com/moveeeax/cra-doc-kit/internal/gapcheck"
	"github.com/moveeeax/cra-doc-kit/internal/kev"
	"github.com/moveeeax/cra-doc-kit/internal/profile"
	"github.com/moveeeax/cra-doc-kit/internal/sbom"
	"github.com/moveeeax/cra-doc-kit/internal/scan"
	"github.com/moveeeax/cra-doc-kit/internal/vex"
)

// Version is overridden at build time with -ldflags "-X ...cli.Version=vX.Y.Z".
var Version = "dev"

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1 // the documents were produced but the policy threshold was breached
	exitUsage  = 2 // bad flags, unreadable or invalid input
)

const usage = `cra-doc-kit — CRA paperwork from the artefacts a build already produces.

Usage:
  cra-doc-kit <command> [flags]

Commands:
  gapcheck   Score an SBOM, scan and VEX against the automatable CRA checks
  vex        Render an OpenVEX document from a scan plus human triage
  annex      Render an Annex VII technical file skeleton
  version    Print the version

Run "cra-doc-kit <command> -h" for the flags of a command.
`

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "gapcheck":
		return wrap(runGapcheck(args[1:], stdout, stderr), stderr)
	case "vex":
		return wrap(runVex(args[1:], stdout, stderr), stderr)
	case "annex":
		return wrap(runAnnex(args[1:], stdout, stderr), stderr)
	case "version":
		fmt.Fprintf(stdout, "cra-doc-kit %s\n", Version)
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "cra-doc-kit: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

// exitError carries an explicit exit code alongside the message.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }

func wrap(err error, stderr io.Writer) int {
	if err == nil {
		return exitOK
	}
	if flag.ErrHelp == err {
		return exitOK
	}
	var ee *exitError
	if errorsAs(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(stderr, "cra-doc-kit: %v\n", ee.err)
		}
		return ee.code
	}
	fmt.Fprintf(stderr, "cra-doc-kit: %v\n", err)
	return exitUsage
}

func errorsAs(err error, target **exitError) bool {
	if e, ok := err.(*exitError); ok {
		*target = e
		return true
	}
	return false
}

// --- gapcheck ---------------------------------------------------------------

func runGapcheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gapcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		sbomPath = fs.String("sbom", "", "CycloneDX SBOM (required)")
		scanPath = fs.String("scan", "", "Grype JSON report")
		vexPath  = fs.String("vex", "", "OpenVEX document")
		kevPath  = fs.String("kev", "", "local copy of the CISA KEV catalog (known_exploited_vulnerabilities.json)")
		format   = fs.String("format", "md", "output format: md or json")
		out      = fs.String("out", "-", "output file, or - for stdout")
		failOn   = fs.String("fail-on", "blocker", "exit 1 when a finding of this severity or worse exists: blocker, warning, info, none")
		stamp    = fs.String("timestamp", "", "RFC 3339 timestamp to stamp the report with (default: now)")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Score an SBOM, scan and VEX against the automatable CRA checks.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sbomPath == "" {
		fs.Usage()
		return fmt.Errorf("--sbom is required")
	}
	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}
	now, err := parseStamp(*stamp)
	if err != nil {
		return err
	}

	in := gapcheck.Input{SBOMPath: *sbomPath, ScanPath: *scanPath, VEXPath: *vexPath, KEVPath: *kevPath, Now: now}
	if in.SBOM, err = sbom.Load(*sbomPath); err != nil {
		return err
	}
	if *scanPath != "" {
		if in.Scan, err = scan.Load(*scanPath); err != nil {
			return err
		}
	}
	if *vexPath != "" {
		if in.VEX, err = loadVEX(*vexPath); err != nil {
			return err
		}
	}
	if *kevPath != "" {
		if in.KEV, err = kev.Load(*kevPath); err != nil {
			return err
		}
	}

	report := gapcheck.Run(in)

	var payload []byte
	switch *format {
	case "md", "markdown":
		payload = []byte(report.Markdown())
	case "json":
		if payload, err = report.JSON(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("--format must be md or json, got %q", *format)
	}
	if err := write(*out, payload, stdout); err != nil {
		return err
	}
	if *out != "-" {
		fmt.Fprintf(stderr, "wrote %s (%d blockers, %d warnings)\n", *out, report.Counts.Blocker, report.Counts.Warning)
	}
	if code := report.ExitCode(threshold); code != 0 {
		return &exitError{code: exitFailed}
	}
	return nil
}

func parseFailOn(s string) (gapcheck.Severity, error) {
	switch strings.ToLower(s) {
	case "blocker":
		return gapcheck.Blocker, nil
	case "warning":
		return gapcheck.Warning, nil
	case "info":
		return gapcheck.Info, nil
	case "none", "":
		return "", nil
	default:
		return "", fmt.Errorf("--fail-on must be blocker, warning, info or none, got %q", s)
	}
}

// --- vex --------------------------------------------------------------------

func runVex(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		scanPath    = fs.String("scan", "", "Grype JSON report (required)")
		triagePath  = fs.String("triage", "", "triage YAML with the analyst decisions")
		profilePath = fs.String("profile", "", "product profile YAML, used for the product identifier and author")
		sbomPath    = fs.String("sbom", "", "CycloneDX SBOM, used as a fallback source of the product identifier")
		kevPath     = fs.String("kev", "", "local copy of the CISA KEV catalog; marks affected and under_investigation statements it lists")
		product     = fs.String("product", "", "product identifier (purl) the statements apply to")
		author      = fs.String("author", "", "author of the statements")
		role        = fs.String("role", "Manufacturer", "role of the author")
		out         = fs.String("out", "-", "output file, or - for stdout")
		stamp       = fs.String("timestamp", "", "RFC 3339 document timestamp (default: now)")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Render an OpenVEX document from a scan plus human triage.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" {
		fs.Usage()
		return fmt.Errorf("--scan is required")
	}
	now, err := parseStamp(*stamp)
	if err != nil {
		return err
	}

	result, err := scan.Load(*scanPath)
	if err != nil {
		return err
	}

	var triage *vex.Triage
	if *triagePath != "" {
		if triage, err = vex.LoadTriage(*triagePath); err != nil {
			return err
		}
	}

	var catalog *kev.Catalog
	if *kevPath != "" {
		if catalog, err = kev.Load(*kevPath); err != nil {
			return err
		}
	}

	opts := vex.Options{
		ProductID: *product,
		Author:    *author,
		Role:      *role,
		Tooling:   "cra-doc-kit " + Version,
		Timestamp: now,
		KEV:       catalog,
	}
	if *profilePath != "" {
		p, err := profile.Load(*profilePath)
		if err != nil {
			return err
		}
		if opts.ProductID == "" {
			opts.ProductID = p.Product.PURL
		}
		if opts.Author == "" {
			opts.Author = p.Manufacturer.LegalName
		}
	}
	if opts.ProductID == "" && *sbomPath != "" {
		doc, err := sbom.Load(*sbomPath)
		if err != nil {
			return err
		}
		if p := doc.Product(); p != nil {
			opts.ProductID = p.PURL
			if opts.ProductID == "" {
				opts.ProductID = p.Key()
			}
		}
	}
	if triage != nil {
		if opts.Author == "" {
			opts.Author = triage.Author
		}
		if triage.Role != "" {
			opts.Role = triage.Role
		}
	}

	doc, warnings, err := vex.Generate(result.Findings, triage, opts)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	payload, err := doc.Marshal()
	if err != nil {
		return err
	}
	if err := write(*out, payload, stdout); err != nil {
		return err
	}
	if *out != "-" {
		counts := doc.CountByStatus()
		kevNote := ""
		if catalog != nil {
			kevNote = fmt.Sprintf(", %d KEV-listed", doc.KEVListed())
		}
		fmt.Fprintf(stderr, "wrote %s (%d statements, %d under_investigation%s)\n",
			*out, len(doc.Statements), counts[vex.StatusUnderInvestigation], kevNote)
	}
	return nil
}

// --- annex ------------------------------------------------------------------

func runAnnex(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("annex", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		sbomPath    = fs.String("sbom", "", "CycloneDX SBOM (required)")
		profilePath = fs.String("profile", "", "product profile YAML (required)")
		scanPath    = fs.String("scan", "", "Grype JSON report")
		vexPath     = fs.String("vex", "", "OpenVEX document")
		kevPath     = fs.String("kev", "", "local copy of the CISA KEV catalog (known_exploited_vulnerabilities.json)")
		out         = fs.String("out", "-", "output file, or - for stdout")
		strict      = fs.Bool("strict", false, "exit 1 if any TODO remains in the rendered file")
		stamp       = fs.String("timestamp", "", "RFC 3339 document timestamp (default: now)")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Render an Annex VII technical file skeleton.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sbomPath == "" || *profilePath == "" {
		fs.Usage()
		return fmt.Errorf("--sbom and --profile are both required")
	}
	now, err := parseStamp(*stamp)
	if err != nil {
		return err
	}

	in := annex.Input{SBOMPath: *sbomPath, ScanPath: *scanPath, VEXPath: *vexPath, KEVPath: *kevPath, Now: now}
	if in.Profile, err = profile.Load(*profilePath); err != nil {
		return err
	}
	if in.SBOM, err = sbom.Load(*sbomPath); err != nil {
		return err
	}
	if *scanPath != "" {
		if in.Scan, err = scan.Load(*scanPath); err != nil {
			return err
		}
	}
	if *vexPath != "" {
		if in.VEX, err = loadVEX(*vexPath); err != nil {
			return err
		}
	}
	if *kevPath != "" {
		if in.KEV, err = kev.Load(*kevPath); err != nil {
			return err
		}
	}

	doc, view, err := annex.Render(in)
	if err != nil {
		return err
	}
	if err := write(*out, []byte(doc), stdout); err != nil {
		return err
	}
	if *out != "-" {
		fmt.Fprintf(stderr, "wrote %s (%d open items)\n", *out, len(view.TODOs))
	}
	if *strict && len(view.TODOs) > 0 {
		fmt.Fprintf(stderr, "%d open items remain: %s\n", len(view.TODOs), strings.Join(view.TODOs, ", "))
		return &exitError{code: exitFailed}
	}
	return nil
}

// --- helpers ----------------------------------------------------------------

func loadVEX(path string) (*vex.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vex: %w", err)
	}
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

func parseStamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--timestamp must be RFC 3339: %w", err)
	}
	return t.UTC(), nil
}

func write(path string, data []byte, stdout io.Writer) error {
	if path == "-" || path == "" {
		_, err := stdout.Write(data)
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
