# Architecture

The orchestrator is a pipeline of small, independently testable stages.  Each stage writes files
that the next one reads, so any stage can be re-run on its own (for example, re-scoring old raw
outputs against a newer ground truth without re-running the tools).

```
            ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
  config ──▶│ baseline.py  │────▶│ runner.py     │────▶│ raw CBOMs    │
            │ sync/discover│     │ tools/*       │     │ logs         │
            └──────────────┘     │ github/docker │     │ manifest.json│
                                 └───────────────┘     └──────┬───────┘
                                                              │
            ┌──────────────┐     ┌───────────────┐     ┌──────▼───────┐
  2CBOM ◀───│ export/      │◀────│ reconcile.py  │◀────│ evaluate/    │
            │ tools.json   │     │ Scorecard     │     │ normalize/   │
            │ priors.json  │     │ reconcile()   │     │ ledger rows  │
            │ report.md    │     └───────────────┘     └──────────────┘
            └──────────────┘
```

## Stages

### 1. Baseline (`orchestrator/baseline.py`)

* `sync_baseline` clones or fast-forwards the corpus repository at the configured ref and records the
  commit SHA (`git rev-parse HEAD`) and `git describe` output.  A local directory can be used instead
  of a URL.
* `discover_cases` lists every top-level directory containing `ground-truth.json` (excluding
  `_tooling` and anything in `baseline.exclude_dirs`).  The language comes from the ground truth
  file, the case id from the directory name (`CSharp` → language `C#`).
* `GroundTruth` is a typed view of `ground-truth.json`: assets with their occurrences, scenarios,
  libraries, canonical descriptors and category facets; the non-asset mentions; the libraries (which
  become `library` assets so library detection is scored like everything else).

### 2. Tools (`orchestrator/tools/`)

A `ToolSpec` (YAML) describes a generator; a `ToolAdapter` runs it.  `CommandToolAdapter` executes
specs declaratively (Docker image or local command, placeholders rendered per case).
`CryptobomForgeAdapter` is a pipeline adapter (CodeQL database → inventory queries → SARIF → forge).
`OracleAdapter` replays the corpus' reference CBOM with optional, seeded degradation.

Version resolution lives in `github.py`: GitHub REST API (`releases/latest`) when reachable, otherwise
`git ls-remote --tags` with semantic-version ordering; pins accept tags or commit SHAs.  For Docker
launchers the pulled image's digest and id are recorded; for local launchers the install log and a
version check.  Whatever a tool writes into `metadata.tools` of its CBOM is recorded as `reported`.

### 3. Runner (`orchestrator/runner.py`)

Creates `results/<run-id>/`, resolves and installs every enabled tool (failures are recorded, not
raised), copies each case into `work/<tool>/<case>/` (without `ground-truth.json` and the reference
CBOM, so tools cannot "find" the answers), runs the adapter, copies the output to
`raw/<tool>/<case>/`, and keeps `manifest.json` current after every step.

### 4. Normalisation (`orchestrator/normalize/`)

`read_cbom` auto-detects the dialect and lifts components to `Detection` objects: asset type, name,
OID, attributes with CycloneDX 1.6 names and normalised enumerations, occurrences (file, line,
offset, symbol, context), and — for algorithms — a canonical `Descriptor` built by the lexicon from
the name plus the structured hints (`AES/GCM/NoPadding` → `aes-gcm-none`, `SHA256withRSA` →
`rsa-sha2-256`, `Kyber768` → `ml-kem-768`).  Referenced assets (`algorithmRef`,
`signatureAlgorithmRef`, cipher-suite algorithm refs) are resolved to names inside the document.

### 5. Evaluation (`orchestrator/evaluate/`)

* `matcher.py` assigns detections to ground-truth assets (see [scoring-model.md](scoring-model.md)).
* `attributes.py` compares attributes of the best matching detection with the ground truth.
* `ledger.py` emits one row per ground-truth asset and one per unmatched detection.
* `scoring.py` aggregates rows for any category (facet filter) into metrics and a composite score.
* `pairwise.py` builds head-to-head tables between two tools.
* `stats.py` has the Beta-posterior arithmetic (no SciPy needed).
* `__init__.py::evaluate_run` drives all of that for a run directory and builds the scorecard document.

### 6. Reconciliation (`orchestrator/reconcile.py`)

`Scorecard` loads `scorecard.json` (with ledger: any category can be scored on demand) or
`priors.json` (precomputed categories only).  `reconcile()` applies the tiered evidence model with
category backoff and returns a `Reconciliation` (preferred tool, weights, confidence, tier, support,
tool versions, explanation).

### 7. Export (`orchestrator/export/`)

`scorecard.json`, `priors.json`, `report.md`, and `twocbom/tools.json`.  See
[output-formats.md](output-formats.md).

## Design decisions

* **Data-driven ground truth.** Nothing in the matcher knows the corpus' asset list; families,
  parameter sets, scenarios and libraries are read from `ground-truth.json`.  A new scenario or a
  new language directory needs no code change.  New *vocabulary* (a brand-new algorithm family the
  lexicon has never seen) is handled by name/OID fallback and can be added to
  `normalize/lexicon.py` in one line.
* **Partial credit over binary detection.** Treating `AES` as a miss plus a false positive would
  hide exactly the behaviour 2CBOM must reason about (a correct but incomplete identity).  Instead
  the identity score and the per-attribute outcomes make incompleteness and incorrectness separate,
  measurable quantities.
* **Rows, not just numbers.** The ledger keeps every outcome, so a category that was never
  precomputed (`language=Go;family=rsa;scenario=S17`) can still be scored exactly at query time,
  and head-to-head statistics can be derived for any pair of tools without re-running anything.
* **Bayesian comparison instead of thresholds.** Comparing two Beta posteriors turns "A was right 7
  times, B 2 times" into a probability that already reflects the amount of evidence; a relevance
  discount pulls it toward 0.5 when the category had to be generalised.
* **Everything records its provenance.** Baseline commit, tool tag/commit/digest, self-reported
  version, scoring-model version and the orchestrator version travel with every output.
