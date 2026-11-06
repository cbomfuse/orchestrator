# cbom-orchestrator

Benchmarks CBOM generators against the [cbomfuse/baseline](https://github.com/cbomfuse/baseline)
ground truth and turns the results into **versioned, per-category reliability priors** that
[2CBOM](https://github.com/cbomfuse/2cbom) uses to settle conflicts between tools.

```
baseline (ground truth)        tools (newest GitHub release)          2CBOM
┌───────────────────┐   run    ┌──────────┬────────┬────────────────┐  │
│ Python Java Go TS │ ───────▶ │ CBOMkit  │ cdxgen │ cryptobom-forge│  │  "A says AES-128-GCM,
│ C#  …any new case │          └──────────┴────────┴────────────────┘  │   B says AES-256-GCM
└───────────────────┘   normalise → match → score per category         │   — whom do I trust?"
                                   │                                   ▼
                       scorecard.json · priors.json · report.md · twocbom/tools.json
                                   │
                        orchestrator reconcile → prefer B, confidence 0.91, tool versions
```

## What it does

1. **Syncs the baseline** and discovers every case (any top-level directory with a `ground-truth.json`), so
   cases you add or remove upstream are picked up automatically.
2. **Resolves the newest version of every tool from GitHub** (latest release → highest tag → branch tip),
   installs it (Docker image or local install), and records tag, commit SHA, image digest and the
   version the tool itself writes into its CBOMs.
3. **Runs every tool on every case** in an isolated workspace, keeping raw outputs and full logs.
4. **Normalises** CycloneDX 1.5/1.6/1.7 and IBM `1.4-cbom-1.0` output into one detection model and
   **matches** it to the ground truth by OID, canonical descriptor (family, parameter set, mode,
   padding, curve, hash) and source location — with partial credit (`AES` for `AES-256-GCM`) and
   lexical false positives (a comment that says "HMAC") identified from the corpus' non-asset mentions.
5. **Scores every (tool, category)**: recall, precision, completeness (did it report the attribute),
   correctness (was it right), locality (did it point at the right lines), composite score, and
   per-attribute statistics — for categories such as language, asset type, primitive, family,
   scenario, library, implicit/PQC — plus pairwise head-to-head tables.
6. **Answers reconciliation queries**: *tools A and B disagree on attribute Y in category X* →
   preferred tool, weights, a Bayesian confidence, the evidence tier used and the exact tool versions.

The reference CBOM shipped with the corpus scores 1.000 on every case through this pipeline
(`make selftest`), which is the acceptance test for the matcher.

## Quick start

```bash
pip install -e .                       # Python >= 3.10; needs git; Docker for cbomkit/cdxgen
orchestrator baseline sync             # clones cbomfuse/baseline into .orchestrator/baseline
orchestrator tools resolve             # newest versions, no install
orchestrator run                       # resolve + install + scan all cases + evaluate + export
orchestrator report latest             # Markdown report
orchestrator reconcile latest --tool-a cbomkit --tool-b cdxgen \
    --category "language=Java;subtype=ae" --attribute parameterSetIdentifier
```

Without Docker or network, `make selftest` runs the pipeline with the built-in `oracle` tools.

Pin versions (`--pin cdxgen=v13.6.0 --pin cbomkit=2.2.0`) to reproduce a run, `--launcher local` to
avoid Docker where a tool supports it, `orchestrator evaluate <run> --baseline <path>` to re-score
old raw outputs against an updated ground truth, and `orchestrator runs diff <run1> <run2>` to see how
scores moved between tool versions.

## Outputs of a run (`results/<run-id>/`)

| File | Purpose |
|---|---|
| `manifest.json` | baseline commit, resolved tool versions (tag, commit, image digest), status of every (tool, case) |
| `raw/<tool>/<case>/` | the CBOM each tool produced (and the SARIF for cryptobom-forge) |
| `logs/` | every command line with stdout/stderr |
| `scorecard.json` | scores per tool and category, pairwise head-to-head tables, the full ledger |
| `priors.json` | the same without the ledger — what 2CBOM ships |
| `twocbom/tools.json` | drop-in `twocbom/knowledge/tools.json` with benchmark-derived `trust` and `strengths` |
| `report.md` | human-readable report with the version table |

Every output states which tool versions produced it: `tools.<id>.{version, tag, commit, image,
image_digest, reported}` in the scorecard, the `benchmark` block in `tools.json`, and `toolVersions`
in every reconciliation answer.

## Using it from 2CBOM

```python
from orchestrator.reconcile import Scorecard

sc = Scorecard.load("results/latest/priors.json")           # or scorecard.json for exact, any-category answers
r = sc.reconcile("cbomkit", "cdxgen", {"language": "Java", "subtype": "ae"}, "parameterSetIdentifier",
                 value_a="128", value_b="256")
r.preferred, r.confidence, r.weights, r.tier, r.versions
```

See [docs/2cbom-integration.md](docs/2cbom-integration.md) for the `tools.json` hand-off and a sketch
of hooking `reconcile()` into 2CBOM's settlement order.

## Adding a tool

Usually one YAML file in `tools.d/` — repository, how to pick the version, the Docker image or local
command, the per-language flag, where the output lands. See [docs/adding-a-tool.md](docs/adding-a-tool.md).
Tools that need a pipeline (cryptobom-forge needs CodeQL first) subclass `ToolAdapter`.

## Repository layout

```
orchestrator/            the package
  baseline.py            corpus checkout, case discovery, ground-truth model
  github.py docker.py    version resolution, downloads, container execution
  tools/                 adapter base, generic YAML adapter, cryptobom-forge pipeline, oracle
  data/tools/*.yaml      built-in tool specs (cbomkit, cdxgen, cryptobom-forge, oracle, oracle-noisy)
  normalize/             lexicon + CycloneDX / IBM-CBOM readers
  evaluate/              matcher, attribute comparison, ledger, scoring, pairwise, statistics
  reconcile.py           Scorecard + reconcile()
  export/                scorecard, priors, report.md, 2CBOM tools.json
  runner.py cli.py
tools.d/                 your tool specs (override or add)
docs/                    architecture, scoring model, output formats, running, 2CBOM integration
tests/                   73 tests; fixtures include the baseline's Python case and 2CBOM example CBOMs
```

Documentation: [architecture](docs/architecture.md) · [scoring model](docs/scoring-model.md) ·
[output formats](docs/output-formats.md) · [running](docs/running.md) ·
[adding a tool](docs/adding-a-tool.md) · [2CBOM integration](docs/2cbom-integration.md)

License: Apache-2.0.
