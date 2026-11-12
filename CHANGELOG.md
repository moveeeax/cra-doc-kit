# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Require Go 1.26 or newer; CI now tests Go 1.26 and 1.27.
- Replace the archived `gopkg.in/yaml.v3` with its maintained successor
  `go.yaml.in/yaml/v3` v3.0.6.
- Bump CI actions to `actions/checkout@v7`, `actions/setup-go@v7` and
  `actions/upload-artifact@v7`.

### Added

- `--kev` on `gapcheck`, `vex` and `annex`: read a local copy of the CISA Known
  Exploited Vulnerabilities catalog. `gapcheck` adds rule VULN-004, a blocker
  for KEV-listed findings left `affected`, `under_investigation` or untriaged
  (Annex I Part II(2), Article 14); `vex` writes a KEV marker into
  `status_notes` of open statements; `annex` lists KEV-listed findings with
  their `dateAdded` in section 2.4.
- Grype `relatedVulnerabilities` are kept as aliases of a finding, so a GHSA
  match resolves to the CVE in the KEV catalog.
- MIT license.
- Dependabot configuration for GitHub Actions and Go modules.

## [0.1.0] - 2026-07-26

### Added

- `gapcheck`: CRA readiness report over a CycloneDX SBOM, a Grype scan and an
  OpenVEX document, with every check mapped to its CRA article or annex.
- `vex`: OpenVEX v0.2.0 document built from a Grype scan plus human triage.
- `annex`: Annex VII technical file skeleton with machine-derivable sections
  filled in and open items marked TODO.

[Unreleased]: https://github.com/moveeeax/cra-doc-kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moveeeax/cra-doc-kit/releases/tag/v0.1.0
