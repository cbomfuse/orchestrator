"""cbom-orchestrator: benchmark CBOM generators against the cbomfuse/baseline ground truth.

The package is organised as a pipeline:

    baseline.py   -> clone/refresh the ground-truth corpus and discover its cases
    tools/        -> generic, versioned adapters that run CBOM generators (Docker or local)
    runner.py     -> execute every (tool, case) pair into an isolated run directory
    normalize/    -> lift CycloneDX 1.5/1.6/1.7 and IBM 1.4-cbom-1.0 output to one detection model
    evaluate/     -> match detections to ground-truth assets and score them per category
    reconcile.py  -> the API 2CBOM calls to settle a conflict between two tools
    export/       -> scorecard.json, report.md, 2CBOM tools.json and reconciliation priors
"""

__version__ = "0.1.0"

# Bump when the ledger/aggregate semantics change (so 2CBOM can refuse stale priors).
SCORING_MODEL_VERSION = "1.0"
# Bump when the scorecard.json layout changes.
SCORECARD_SCHEMA_VERSION = "1.0"
