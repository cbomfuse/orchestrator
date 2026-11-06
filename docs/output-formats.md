# Output formats

All files live in `results/<run-id>/`.  `results/latest` is a symlink to the newest run.

## `manifest.json` (written by `orchestrator run`)

```jsonc
{
  "runId": "20261105-213000", "startedAt": "...", "finishedAt": "...",
  "host": {"hostname": "...", "platform": "...", "python": "3.12.3", "orchestrator": "0.1.0"},
  "config": { ...the effective orchestrator.yaml... },
  "baseline": {"repo": "https://github.com/cbomfuse/baseline.git", "ref": "main",
               "commit": "6102ae18…", "describe": "6102ae1", "path": "...", "synced": true,
               "cases": [{"id": "Python", "language": "Python", "dir": "...", "groundTruth": "...",
                          "referenceCbom": "...", "sourceFile": "crypto_showcase.py"}, ...]},
  "tools": {
    "cdxgen": {"tool": "cdxgen", "name": "cdxgen", "repo": "https://github.com/CycloneDX/cdxgen",
               "strategy": "release", "tag": "v13.6.0", "version": "13.6.0", "commit": "e0078793…",
               "resolved_at": "...", "source": "api", "url": "...", "launcher": "docker",
               "image": "ghcr.io/cyclonedx/cdxgen:v13.6.0", "image_digest": "ghcr.io/cyclonedx/cdxgen@sha256:…",
               "image_id": "sha256:…", "reported": null, "components": {...}, "notes": [...], "spec": {...}},
    "cryptobom-forge": {..., "components": {"codeql": {"tag": "codeql-bundle-v2.27.4", "cliVersion": "2.27.4", ...},
                                            "queryPacks": {"python-queries": "1.6.1", ...}, "forge": {...}}}
  },
  "runs": [{"tool": "cdxgen", "toolVersion": "13.6.0", "case": "Python", "language": "Python",
            "status": "ok", "output": "raw/cdxgen/Python/cbom.cdxgen.json", "exitCode": 0,
            "durationSeconds": 41.2, "log": "logs/cdxgen/Python.log", "command": [...], "notes": [],
            "startedAt": "...", "finishedAt": "..."}, ...]
}
```

`status` ∈ `ok` (output parsed), `empty` (no components), `failed`, `timeout`, `unsupported` (tool
has no configuration for the language), `install-failed`.

## `scorecard.json` (written by `evaluate`)

```jsonc
{
  "schemaVersion": "1.0", "scoringModelVersion": "1.0", "orchestrator": {"version": "0.1.0"},
  "run": {"id": "...", "startedAt": "...", "finishedAt": "...", "host": {...}, "config": {"scoring": {...}}},
  "baseline": {"repo", "ref", "commit", "describe", "evaluatedCommit", "evaluatedDescribe", "evaluatedAt", ...},
  "cases": [{"id", "language", "sourceFile", "stats": {"assets": 90, "byType": {...}, "occurrences": 195, ...}}],
  "tools": {"<tool>": {"version", "tag", "commit", "image", "image_digest", "reported": {"name", "version", "format", "specVersion"}, "twocbom": {...}, ...}},
  "runs": [ ...manifest runs + "evaluation": {"detections", "matchedDetections", "unmatched", "detectedAssets", ...} ],
  "coverage": {"<tool>": {"<language>": "<status>"}},
  "scores": {
    "<tool>": {
      "overall": <aggregate>,
      "byCategory": {"language=Java": <aggregate>, "subtype=hash": <aggregate>, "language=Go;subtype=kdf": <aggregate>, ...},
      "strengths": ["parameterSetIdentifier", "mode", ...],
      "coverage": {...}
    }
  },
  "pairwise": {"cbomkit|cdxgen": {"*": {"*": <counts>, "mode": <counts>, ...}, "language=Java": {...}, ...}},
  "summary": {"<tool>": {"support", "detected", "recall", "precision", "completeness", "correctness", "locality", "score", "falsePositives", "lexicalFalsePositives"}},
  "ledger": [ <row>, ... ]
}
```

### `<aggregate>`

```jsonc
{"support": 166, "detected": 120, "exact": 97, "truePositives": 131, "falsePositives": 9, "lexicalFalsePositives": 2,
 "identity": 0.88, "recall": 0.723, "recallInterval": [0.65, 0.78], "precision": 0.936, "completeness": 0.81,
 "correctness": 0.93, "locality": 0.77, "score": 0.802, "scoreShrunk": 0.80,
 "attributes": {"mode": {"expected": 40, "reported": 31, "correct": 29.0, "completeness": 0.775, "correctness": 0.935}, ...}}
```

### `<counts>` (head-to-head)

`aWins`, `bWins`, `bothWrong`, `agree`, `agreeWrong`, `aOnly`, `bOnly`, `bothMissed`, `compared`.
Pair keys are sorted (`a|b` with `a < b`); the `Scorecard` API swaps the counts when asked the other
way round.

### Ledger row (`kind: gt`)

```jsonc
{"tool": "cdxgen", "toolVersion": "13.6.0", "case": "Python", "language": "Python", "kind": "gt",
 "assetId": "aes-256-gcm", "name": "AES-256-GCM", "assetType": "algorithm", "subtype": "ae", "family": "aes",
 "scenarios": ["S11"], "libraries": ["lib.pyca"], "implicit": false, "pqc": false, "scored": true,
 "detected": true, "matchLevel": "partial", "identityScore": 0.6667, "located": true, "ambiguous": false,
 "detections": 1, "detectionRefs": ["crypto/algorithm/aes-gcm"],
 "attributes": {"primitive": {"expected": "ae", "reported": "ae", "correct": 1.0},
                "parameterSetIdentifier": {"expected": "256", "reported": null, "correct": 0.0},
                "identity": {"expected": "aes-256-gcm", "reported": "aes-gcm", "correct": 0.6667}, ...},
 "completeness": 0.75, "correctness": 1.0,
 "locations": {"expected": 3, "matched": 2, "reported": 2, "reportedMatched": 2},
 "bestDetection": {"ref": "crypto/algorithm/aes-gcm", "name": "aes-gcm"}}
```

Ledger row (`kind: fp`): `tool, toolVersion, case, language, assetId: null, name, ref, assetType,
subtype, family, lexical, lines, files, descriptor`.

## `priors.json`

`scorecard.json` without `ledger` (plus `"ledgerIncluded": false`).  `Scorecard.load()` accepts it;
reconciliation then uses the precomputed categories and pairwise tables.

## `twocbom/tools.json`

Same shape as `twocbom/knowledge/tools.json` with an extra `benchmark` block per tool:

```jsonc
{
  "$comment": "...", "version": "orchestrator-<run-id>", "generated": "...", "scoringModelVersion": "1.0",
  "baseline": {"repo": "...", "commit": "6102ae18…", "ref": "main"},
  "default": {"trust": 50, "detectionMethod": "unknown", "strengths": []},
  "tools": {
    "cbomkit": {
      "aliases": ["cbomkit", "cbom-kit", "ibm cbomkit", "cbomkit-action", ..., "IBM/CBOMkit"],
      "trust": 83, "detectionMethod": "static-source",
      "strengths": ["parameterSetIdentifier", "mode", "cryptoFunctions", "primitive"],
      "benchmark": {"version": "2.3.0", "tag": "v2.3.0", "commit": "34a3d960…",
                    "image": "ghcr.io/cbomkit/cbomkit-action:2.3.0", "imageDigest": "…",
                    "reportedVersion": "2.3.0", "score": 0.83, "support": 353, "recall": 0.74, "precision": 0.95,
                    "completeness": 0.84, "correctness": 0.93, "coverage": {"Java": "ok", "TypeScript": "unsupported", ...}}
    }
  }
}
```

The self-reported tool name from the CBOM metadata is appended to `aliases` so 2CBOM's alias lookup
resolves the source to the benchmarked profile.

## `report.md`

Ground-truth table, tool versions (tag, commit, image digest, self-reported version, CodeQL bundle and
query-pack versions), coverage matrix, overall scores, per-language / asset-type / primitive /
family / PQC tables, attribute quality, head-to-head summary, most frequent false positives, run log.
