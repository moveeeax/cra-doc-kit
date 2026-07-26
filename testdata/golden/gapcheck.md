# CRA Gap Check — ledger-gateway 4.6.2

Generated: 2026-07-20T10:00:00Z by cra-doc-kit

| Input | File |
|---|---|
| SBOM | `examples/sbom.cdx.json` |
| Vulnerability scan | `examples/scan.grype.json` |
| VEX | `examples/vex.json` |

**Result: 1 blocker(s), 3 warning(s), 2 note(s), 9 passed check(s) across 9 components.**

## Summary

| Check | Result | CRA reference |
|---|---|---|
| SBOM-007 Every component carries a package URL | BLOCKER | Annex I Part II(1) |
| SBOM-008 Components identify their supplier | WARNING | Annex VII(2)(b) |
| SBOM-009 Components declare licence information | WARNING | Annex VII(2)(b) |
| VULN-003 No vulnerability is left under investigation at release | WARNING | Annex I Part II(2) |
| ECO-001 Package ecosystems are within the tested coverage | INFO | cra-doc-kit scope |
| SBOM-010 Components carry integrity hashes | INFO | Annex I Part I(2)(f) |
| SBOM-001 SBOM is in a commonly used machine-readable format | PASS | Annex I Part II(1) |
| SBOM-002 SBOM names the product it describes | PASS | Annex VII(1)(a)-(b) |
| SBOM-003 SBOM records when it was produced | PASS | Annex I Part II(1) |
| SBOM-004 SBOM records who or what produced it | PASS | Annex VII(2)(b) |
| SBOM-005 SBOM lists components | PASS | Annex I Part II(1) |
| SBOM-006 Every component carries a version | PASS | Annex I Part II(1) |
| SBOM-011 Top-level dependencies are identifiable | PASS | Annex I Part II(1) |
| VULN-001 Known vulnerabilities are enumerated | PASS | Annex I Part I(2)(a) |
| VULN-002 Every known vulnerability has a documented decision | PASS | Annex I Part II(2) |

## Blockers

### SBOM-007 — Every component carries a package URL

*Reference: Annex I Part II(1)*

1 of 9 components has no purl; VEX statements cannot reference them unambiguously.

- `acme-crypto-helpers@1.2.0`

## Warnings

### SBOM-008 — Components identify their supplier

*Reference: Annex VII(2)(b)*

1 of 9 components name no supplier, author or publisher.

- `pkg:npm/left-pad@1.3.0`

### SBOM-009 — Components declare licence information

*Reference: Annex VII(2)(b)*

2 of 9 components declare no licence.

- `acme-crypto-helpers@1.2.0`
- `pkg:npm/left-pad@1.3.0`

### VULN-003 — No vulnerability is left under investigation at release

*Reference: Annex I Part II(2)*

1 finding is still under_investigation. That is an honest state to ship, but it must be closed before the technical file is signed.

- `CVE-2023-44487 (High) golang.org/x/net`

## Notes

### ECO-001 — Package ecosystems are within the tested coverage

*Reference: cra-doc-kit scope*

npm: 3, golang: 2, maven: 2, pypi: 1, unknown: 1. Ecosystems outside golang/maven/npm are reported but not covered by the fixed-price scope.

- `pypi`
- `unknown`

### SBOM-010 — Components carry integrity hashes

*Reference: Annex I Part I(2)(f)*

2 of 9 components carry a hash. Hashes are not required by the CRA but make the SBOM verifiable against the shipped artefact.

## Scope of this check

This report is a machine-generated readiness check over an SBOM, a vulnerability scan and a VEX document. It does not assess the essential requirements of Annex I Part I that depend on the product's design, and it is not a conformity assessment. The author of this report is not a notified body and issues no Declaration of Conformity.
