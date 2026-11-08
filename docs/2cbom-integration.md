# Using orchestrator from 2CBOM

2CBOM settles every `(asset, attribute)` conflict by a total order (`origin rank > tool strength > tool trust > confidence > value`), with `trust` and `strengths` read from `twocbom/knowledge/tools.json`.  The orchestrator feeds that order in two ways.

## Benchmark-derived `tools.json` 
```bash
orchestrator run
orchestrator export twocbom latest --out /path/to/2cbom/twocbom/knowledge/tools.json
```

* `trust` becomes the tool's overall benchmark score (0–100).
* `strengths` becomes the list of attributes the tool reports correctly ≥ 80% of the time with at
  least five observations.
* `aliases` keeps the hand-maintained aliases from the tool spec and adds the name the tool writes
  into its own CBOMs, so `KnowledgeBase.tool_profile()` resolves the source.
* `benchmark` records tag, commit, image digest, self-reported version, scores and language coverage. 2CBOM's `provenance.knowledgeBaseVersion` can cite `version` (`orchestrator-<run-id>`).

Merging becomes reproducible against a stated benchmark.

## Category-aware reconciliation (a rule-level hook)
`tools.json` carries one trust number per tool.  The scorecard knows that CBOMkit may be excellent
on Java block-cipher modes and weak on Go key sizes.  `Scorecard.reconcile()` answers the question
2CBOM's settlement rule actually asks:

```python
from orchestrator.reconcile import Scorecard

# priors.json works too (precomputed categories only)
sc = Scorecard.load("results/latest/scorecard.json")   
r = sc.reconcile(
    tool_a="cbomkit", tool_b="cdxgen",
    category={"language": "Java", "assetType": "algorithm", "subtype": "ae"},
    attribute="parameterSetIdentifier", # 2CBOM names (parameterSet, family, …) are accepted
    value_a="128", value_b="256",
)
r.preferred      # "cdxgen"
r.weights        # {"cbomkit": 0.09, "cdxgen": 0.91}
r.confidence     # 0.91 
r.decision       # "prefer-b" | "prefer-a" | "undecided"
r.tier           # "head-to-head" | "attribute" | "category" | "global" | "completeness"
r.category_used  # the category after backoff, e.g. {"assetType": "algorithm", "subtype": "ae"}
r.versions       # {"cbomkit": "2.3.0", "cdxgen": "13.6.0"}
r.explanation    # human-readable evidence trail
```

`r.to_dict()` is JSON-serialisable and is what the CLI prints with `--json`.

### Mapping a 2CBOM conflict to a query
| 2CBOM | orchestrator |
|---|---|
| `Source.tool` (after alias resolution) | `tool_a` / `tool_b` — the spec ids (`cbomkit`, `cdxgen`, `cryptobom-forge`) |
| asset type of the canonical asset | `assetType` facet |
| `primitive` / material `type` / protocol `type` | `subtype` facet |
| descriptor `family` | `family` facet (lexicon spelling: `aes`, `rsa`, `sha2`, `ml-kem`, …) |
| language of the evidence location (file extension) | `language` facet (`Python`, `Java`, `Go`, `TypeScript`, `C#`) |
| attribute name in the `Attr`/`Conflict` fact | `attribute` (`parameterSet` → `parameterSetIdentifier`, `family`/`hash`/`descriptor` → `identity`) |
| the two conflicting values | `value_a` / `value_b` (optional; enables the completeness tier and value evidence) |

Unknown facets are ignored by the backoff; an empty category uses the global scores.

### Sketch of a settlement hook
In `twocbom/rules/settle.py` the candidate order is `_sort_key`.  A minimal integration replaces the
scalar `trust` by the reconciliation weight for the pair that actually conflicts:

```python
# twocbom/rules/settle.py (sketch -- adapt to the facts available in the working memory)
from orchestrator.reconcile import Scorecard
PRIORS = Scorecard.load(os.environ.get("TWOCBOM_PRIORS", "priors.json"))

def _benchmark_weight(wm, cid, name, cand, tool_cands):
    others = [c for c in tool_cands if c.origin != cand.origin]
    if not others:
        return 0.0
    # {"language": ..., "assetType": ..., "subtype": ..., "family": ...}
    cat = category_of(wm, cid) 
    r = PRIORS.reconcile(tool_of(wm, cand.origin), tool_of(wm, others[0].origin), cat, name,
                         U(cand.value_json), U(others[0].value_json))
    return r.weights[tool_of(wm, cand.origin)] if r.decision != "undecided" else 0.0

def _sort_key(a):
    return (-_origin_rank(a.origin), -a.strength, -_benchmark_weight(...), -a.trust, -a.confidence, a.value_json, a.origin)
```

Record `r.confidence`, `r.tier`, `r.category_used` and `r.versions` in the `Conflict` fact's
`candidates_json` so `twocbom explain` can show why a value won and which tool versions the
decision rests on. Keep `undecided` results neutral so the existing order still breaks the tie.

## Versioning discipline
* The scorecard's `scoringModelVersion` changes when the matching/scoring rules change; 2CBOM should
  refuse priors with a version it does not expect.
* Every reconciliation answer carries `toolVersions`.  If the CBOM being merged was produced by a
  different version of a tool than the one benchmarked, 2CBOM can downgrade the confidence or warn —
  the self-reported version in the CBOM's `metadata.tools` is exactly what the orchestrator stores
  as `tools.<id>.reported.version`.
* `orchestrator runs diff <old> <new>` shows how trust moved between tool releases; nightly runs
  (`.github/workflows/benchmark.yml`) keep `priors.json` current.
