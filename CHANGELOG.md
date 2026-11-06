# Changelog

## 0.1.0 — 2026-11-05

Initial release.

- Baseline sync and automatic case discovery (`cbomfuse/baseline`).
- Generic YAML tool adapters (Docker or local), newest-release resolution with commit/digest recording.
- Built-in tools: CBOMkit (cbomkit-action image), cdxgen, cryptobom-forge (with CodeQL bundle pipeline),
  plus `oracle`/`oracle-noisy` for self-tests.
- Normalisers for CycloneDX 1.5/1.6/1.7 and IBM 1.4-cbom-1.0.
- Matching (OID → descriptor slots → source location), attribute scoring, lexical false positives.
- Category scorecard, pairwise head-to-head statistics, Bayesian reconciliation API with backoff.
- Exports: `scorecard.json`, `priors.json`, `report.md`, 2CBOM `tools.json`.
