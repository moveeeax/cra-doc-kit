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
