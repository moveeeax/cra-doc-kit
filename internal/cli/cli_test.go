package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate examples/vex.json and the golden files")

// stamp keeps every generated document reproducible.
const stamp = "2026-07-20T10:00:00Z"

// run executes the CLI from the repository root, so the paths that end up
// inside the generated documents are the ones the README tells people to type.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Chdir(filepath.Join("..", ".."))
	var out, errBuf bytes.Buffer
	code = Run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run: go test ./internal/cli -update): %v", err)
	}
	if got != string(want) {
		t.Errorf("output does not match %s.\nRe-run with -update after checking the diff:\n%s",
			path, firstDiff(string(want), got))
	}
}

// firstDiff reports the first differing line, which is all a reviewer needs to
// decide whether a golden change is intended.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + itoa(i+1) + ":\n  want: " + wl + "\n  got:  " + gl
		}
	}
	return "(no line differs; check trailing whitespace)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestVexMatchesCommittedExample proves the command in the README reproduces
// the committed examples/vex.json byte for byte.
func TestVexMatchesCommittedExample(t *testing.T) {
	code, stdout, stderr := run(t,
		"vex",
		"--scan", "examples/scan.grype.json",
		"--triage", "examples/triage.yaml",
		"--profile", "examples/product.yaml",
		"--timestamp", stamp,
	)
	if code != 0 {
		t.Fatalf("exit = %d, stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr:\n%s", stderr)
	}

	if *update {
		if err := os.WriteFile(filepath.Join("examples", "vex.json"), []byte(stdout), 0o644); err != nil {
			t.Fatalf("write examples/vex.json: %v", err)
		}
		return
	}
	want, err := os.ReadFile(filepath.Join("examples", "vex.json"))
	if err != nil {
		t.Fatalf("read examples/vex.json: %v", err)
	}
	if stdout != string(want) {
		t.Errorf("regenerating examples/vex.json produced different output:\n%s", firstDiff(string(want), stdout))
	}
}

func TestGapcheckMarkdown(t *testing.T) {
	code, stdout, _ := run(t,
		"gapcheck",
		"--sbom", "examples/sbom.cdx.json",
		"--scan", "examples/scan.grype.json",
		"--vex", "examples/vex.json",
		"--timestamp", stamp,
		"--fail-on", "none",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 with --fail-on none", code)
	}
	golden(t, "gapcheck.md", stdout)
}

func TestGapcheckJSON(t *testing.T) {
	code, stdout, _ := run(t,
		"gapcheck",
		"--sbom", "examples/sbom.cdx.json",
		"--scan", "examples/scan.grype.json",
		"--vex", "examples/vex.json",
		"--format", "json",
		"--timestamp", stamp,
		"--fail-on", "none",
	)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	golden(t, "gapcheck.json", stdout)
}

func TestAnnex(t *testing.T) {
	code, stdout, _ := run(t,
		"annex",
		"--sbom", "examples/sbom.cdx.json",
		"--profile", "examples/product.yaml",
		"--scan", "examples/scan.grype.json",
		"--vex", "examples/vex.json",
		"--timestamp", stamp,
	)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	golden(t, "annex-vii.md", stdout)
}

func TestGapcheckFailsOnBlockersByDefault(t *testing.T) {
	code, _, _ := run(t,
		"gapcheck",
		"--sbom", "examples/sbom.cdx.json",
		"--scan", "examples/scan.grype.json",
		"--vex", "examples/vex.json",
		"--timestamp", stamp,
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1: the example SBOM has a component with no purl", code)
	}
}

func TestGapcheckWritesToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "reports", "gap.md")
	code, stdout, stderr := run(t,
		"gapcheck",
		"--sbom", "examples/sbom.cdx.json",
		"--out", out,
		"--fail-on", "none",
		"--timestamp", stamp,
	)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty when --out is a file, got %d bytes", len(stdout))
	}
	if !strings.Contains(stderr, "wrote "+out) {
		t.Errorf("stderr = %q, want a confirmation naming the file", stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the tool did not create the nested output directory: %v", err)
	}
	if !strings.Contains(string(data), "# CRA Gap Check") {
		t.Error("the written file is not the report")
	}
}

func TestAnnexStrictFailsWhileTODOsRemain(t *testing.T) {
	code, _, stderr := run(t,
		"annex",
		"--sbom", "examples/sbom.cdx.json",
		"--profile", "examples/product.yaml",
		"--out", filepath.Join(t.TempDir(), "annex.md"),
		"--strict",
		"--timestamp", stamp,
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1 with --strict and open items", code)
	}
	if !strings.Contains(stderr, "open items remain") {
		t.Errorf("stderr = %q, want it to list the open items", stderr)
	}
}

func TestVexWarnsAboutTriageEntriesThatMatchNothing(t *testing.T) {
	dir := t.TempDir()
	triage := filepath.Join(dir, "triage.yaml")
	if err := os.WriteFile(triage, []byte("statements:\n  - vulnerability: CVE-1999-0001\n    status: fixed\n"), 0o644); err != nil {
		t.Fatalf("write triage: %v", err)
	}
	code, _, stderr := run(t,
		"vex",
		"--scan", "examples/scan.grype.json",
		"--product", "pkg:oci/example@sha256:abc",
		"--author", "Example GmbH",
		"--triage", triage,
		"--timestamp", stamp,
	)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr, "CVE-1999-0001") {
		t.Errorf("stderr = %q, want a warning about the unmatched triage entry", stderr)
	}
}

func TestVexRejectsInvalidTriage(t *testing.T) {
	dir := t.TempDir()
	triage := filepath.Join(dir, "triage.yaml")
	body := "statements:\n  - vulnerability: CVE-2021-44228\n    status: not_affected\n"
	if err := os.WriteFile(triage, []byte(body), 0o644); err != nil {
		t.Fatalf("write triage: %v", err)
	}
	code, _, stderr := run(t,
		"vex",
		"--scan", "examples/scan.grype.json",
		"--profile", "examples/product.yaml",
		"--triage", triage,
	)
	if code != 2 {
		t.Errorf("exit = %d, want 2 for an invalid triage file", code)
	}
	if !strings.Contains(stderr, "requires a justification") {
		t.Errorf("stderr = %q, want the validation message", stderr)
	}
}

func TestVexTakesTheProductIdentifierFromTheSBOM(t *testing.T) {
	code, stdout, stderr := run(t,
		"vex",
		"--scan", "examples/scan.grype.json",
		"--sbom", "examples/sbom.cdx.json",
		"--author", "Example GmbH",
		"--timestamp", stamp,
	)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "pkg:oci/ledger-gateway@sha256:") {
		t.Error("the product identifier was not taken from metadata.component")
	}
	if !strings.Contains(stdout, `"status": "under_investigation"`) {
		t.Error("findings with no triage should be under_investigation")
	}
}

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown command", []string{"audit"}},
		{"gapcheck without sbom", []string{"gapcheck"}},
		{"annex without profile", []string{"annex", "--sbom", "examples/sbom.cdx.json"}},
		{"vex without scan", []string{"vex"}},
		{"unreadable sbom", []string{"gapcheck", "--sbom", "does/not/exist.json"}},
		{"bad format", []string{"gapcheck", "--sbom", "examples/sbom.cdx.json", "--format", "pdf"}},
		{"bad fail-on", []string{"gapcheck", "--sbom", "examples/sbom.cdx.json", "--fail-on", "yes"}},
		{"bad timestamp", []string{"gapcheck", "--sbom", "examples/sbom.cdx.json", "--timestamp", "yesterday"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, tc.args...)
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if stderr == "" {
				t.Error("nothing was written to stderr")
			}
		})
	}
}

func TestVersionAndHelp(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != 0 || !strings.HasPrefix(stdout, "cra-doc-kit ") {
		t.Errorf("version: exit %d, stdout %q", code, stdout)
	}
	code, stdout, _ = run(t, "--help")
	if code != 0 || !strings.Contains(stdout, "gapcheck") {
		t.Errorf("help: exit %d, stdout %q", code, stdout)
	}
}
