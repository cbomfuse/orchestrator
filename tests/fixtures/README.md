# Test fixtures

- `baseline-mini/Python/` — the Python case of [cbomfuse/baseline](https://github.com/cbomfuse/baseline)
  (commit `6102ae1`, Apache-2.0): `ground-truth.json`, the reference `cbom.cdx.json` and the program.
  It is used as a self-contained corpus so the test-suite does not need network access.
- `cboms/` — synthetic example outputs of several CBOM generators shipped with
  [cbomfuse/2cbom](https://github.com/cbomfuse/2cbom) (`examples/`, Apache-2.0).  They cover CycloneDX
  1.6, CycloneDX 1.7 and the IBM `1.4-cbom-1.0` dialect and are only used to test the normalisers.
- `mini-gt.json` — a tiny hand-written ground truth with known answers for the matcher tests.
