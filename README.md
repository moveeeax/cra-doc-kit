# cra-doc-kit

Turn the artefacts your build already produces — a CycloneDX SBOM and a
vulnerability scan — into the paperwork the EU Cyber Resilience Act
(Regulation (EU) 2024/2847) asks for.

Three commands, one static binary, no service to sign up to:

| Command | Output |
|---|---|
| `gapcheck` | A CRA readiness report over an SBOM, a scan and a VEX document, with every check mapped to the article or annex it comes from |
| `vex` | An [OpenVEX](https://openvex.dev) v0.2.0 document built from the scan plus your written triage decisions |
| `annex` | An Annex VII technical file skeleton, with the machine-derivable sections filled in and everything else marked TODO |

## What it deliberately does not do

- **It does not triage for you.** A finding with no human decision is written
  out as `under_investigation`, never as `not_affected`. There is no
  reachability analysis and no heuristic that guesses at exploitability.
- **It does not write prose you did not write.** Sections of the technical file
  that depend on your design decisions are rendered as a visible
  `TODO — set <field> in the product profile`, not as generated filler.
- **It does not assess conformity.** It is not a notified body, it does not
  produce a Declaration of Conformity, and nothing it emits is legal advice.
- Only CycloneDX SBOMs and Grype JSON scans are read, and only the npm, Go and
  Maven ecosystems are covered by the tested scope. Other package types are
  reported and flagged as outside it.

## Install

```sh
go install github.com/moveeeax/cra-doc-kit/cmd/cra-doc-kit@latest
```

Or from a clone:

```sh
make build   # ./bin/cra-doc-kit
```

Go 1.24 or newer. The only dependency is `gopkg.in/yaml.v3`.

## Usage example

Everything below runs against the fictional product shipped in `examples/`.
Clone the repository and run it as-is — no credentials, no network.

```sh
git clone https://github.com/moveeeax/cra-doc-kit
cd cra-doc-kit
make build
mkdir -p out
```

**1. Turn the scan plus your triage decisions into OpenVEX.**

```sh
./bin/cra-doc-kit vex \
  --scan examples/scan.grype.json \
  --triage examples/triage.yaml \
  --profile examples/product.yaml \
  --out out/vex.json
```

```
wrote out/vex.json (5 statements, 1 under_investigation)
```

Four of the five findings are decided in `examples/triage.yaml`. The fifth is
not mentioned there, so it comes out as `under_investigation` rather than being
quietly assumed away (statement abridged):

```json
{
  "vulnerability": { "name": "CVE-2023-44487" },
  "products": [ { "@id": "pkg:oci/ledger-gateway@sha256:9f2c…" } ],
  "status": "under_investigation"
}
```

**2. Score the release.**

```sh
./bin/cra-doc-kit gapcheck \
  --sbom examples/sbom.cdx.json \
  --scan examples/scan.grype.json \
  --vex out/vex.json \
  --out out/gap-check.md
```

```
wrote out/gap-check.md (1 blockers, 3 warnings)
```

Exit code 1, because the example SBOM contains a vendored library with no
package URL. That is the point — `gapcheck` is meant to be wired into CI.
`--fail-on warning|info|none` moves the threshold.

The report names each gap and the requirement behind it:

```
| Check                                          | Result  | CRA reference      |
|------------------------------------------------|---------|--------------------|
| SBOM-007 Every component carries a package URL | BLOCKER | Annex I Part II(1) |
| SBOM-008 Components identify their supplier    | WARNING | Annex VII(2)(b)    |
| VULN-003 No vulnerability is left under
           investigation at release              | WARNING | Annex I Part II(2) |
```

`--format json` emits the same report for machines.

**3. Render the technical file.**

```sh
./bin/cra-doc-kit annex \
  --sbom examples/sbom.cdx.json \
  --profile examples/product.yaml \
  --scan examples/scan.grype.json \
  --vex out/vex.json \
  --out out/annex-vii.md
```

```
wrote out/annex-vii.md (5 open items)
```

`out/annex-vii.md` follows the seven headings of Annex VII. The SBOM summary,
the licence and ecosystem breakdown, the vulnerability tables and the Annex I
Part II applicability rows are filled from real data; the five facts the profile
does not carry yet are listed at the bottom under **Open items**. Add
`--strict` to make an unfinished file fail the build.

A rendered copy of all three outputs is committed under
[`testdata/golden/`](testdata/golden) if you want to read them before running
anything.

## The two files you write by hand

**[`examples/product.yaml`](examples/product.yaml)** — the product profile: what
the product is for, who the manufacturer is, how long it is supported, where the
disclosure policy lives. Unknown keys are rejected on load, so a typo cannot
silently drop a fact out of the technical file.

**[`examples/triage.yaml`](examples/triage.yaml)** — one entry per
vulnerability. Validated against the OpenVEX rules before anything is written:
`not_affected` needs a justification from the five machine-readable values or an
impact statement, `affected` needs an action statement, and an entry that
matches no finding is reported as a warning so stale triage does not rot in
place.

## Reproducibility

Every command accepts `--timestamp`, and the OpenVEX `@id` is derived from the
statement content. The same inputs produce byte-identical output, so these
documents can be committed and diffed per release. The test suite asserts it:
`examples/vex.json` in this repository is regenerated and compared on every run.

## Development

```sh
make test     # go test -race ./...
make lint     # gofmt + go vet
make examples # regenerate out/ from examples/
```

Golden files live in `testdata/golden/`. After an intentional change to the
output, review the diff and refresh them with:

```sh
go test ./internal/cli -update
```

## Status and scope

v0. Built as the delivery tool behind a fixed-price CRA readiness engagement,
and published because it is more useful in the open than in a private consulting
folder. Interfaces may still move.

The CRA requirement wording used in the reports and in the Annex VII skeleton is
a working paraphrase for navigation. The text of Regulation (EU) 2024/2847
governs, and the manufacturer remains responsible for the technical file, the
conformity assessment and the declaration of conformity.
