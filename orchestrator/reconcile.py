"""The API 2CBOM calls: *given tools A and B disagreeing about attribute Y of an asset in category X,
whose value should win, and how sure are we?*

Evidence is consulted in tiers, from the most direct to the most general, and within each tier the
requested category is backed off one facet at a time until enough ground-truth support exists:

1. **head-to-head** -- on the corpus, A and B both reported Y for the same assets and disagreed;
   count who was right.  ``p = P(theta > 0.5)`` with ``theta ~ Beta(aWins + 1, bWins + 1)``.
2. **attribute** -- A's and B's independent correctness rates for Y in the category;
   ``p = P(theta_A > theta_B)`` from their Beta posteriors.
3. **category** -- the composite category scores (recall, precision, completeness, correctness,
   locality) treated as rates with the category support as evidence.
4. **global** -- the tools' overall scores (the same numbers exported to 2CBOM as ``trust``).

Backing off makes the evidence less relevant, so the probability is pulled toward 0.5 by a relevance
factor ``1 / (1 + decay * steps)``.  The result carries the probability that A is the more reliable
source, weights for both tools, a decision (``prefer-a`` / ``prefer-b`` / ``undecided``), the tier and
category that produced it, the support behind it, and a human-readable explanation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from . import SCORING_MODEL_VERSION
from .config import DEFAULT_CONFIG
from .evaluate.pairwise import head_to_head, pair_key, swap_counts
from .evaluate.scoring import (FACET_COMBOS, aggregate, attribute_evidence, category_key, fp_matches, parse_category,
                               row_matches)
from .evaluate.stats import posterior, prob_above_half, prob_greater

# Facets dropped first when a category has too little support (least informative first).
DEFAULT_BACKOFF_ORDER = ("case", "scenario", "library", "implicit", "pqc", "language", "family", "subtype", "assetType")

# 2CBOM attribute names -> orchestrator (CycloneDX 1.6) attribute names
TWOCBOM_ATTRIBUTE_ALIASES = {
    "parameterset": "parameterSetIdentifier", "parameter_set": "parameterSetIdentifier", "parameterSet": "parameterSetIdentifier",
    "keysize": "parameterSetIdentifier", "keySize": "parameterSetIdentifier", "family": "identity", "descriptor": "identity",
    "hash": "identity", "cryptofunctions": "cryptoFunctions", "functions": "cryptoFunctions",
    "classicalsecuritylevel": "classicalSecurityLevel", "nistquantumsecuritylevel": "nistQuantumSecurityLevel",
    "securityLevel": "classicalSecurityLevel", "quantumSecurityLevel": "nistQuantumSecurityLevel",
    "ciphersuites": "cipherSuites", "signaturealgorithm": "signatureAlgorithmRef", "signatureAlgorithm": "signatureAlgorithmRef",
    "subjectpublickeyalgorithm": "subjectPublicKeyRef", "subjectPublicKeyAlgorithm": "subjectPublicKeyRef",
    "subjectname": "subjectName", "issuername": "issuerName", "notvalidbefore": "notValidBefore", "notvalidafter": "notValidAfter",
    "algorithmref": "algorithmRef", "algorithm": "algorithmRef", "materialtype": "type", "protocoltype": "type",
}


def normalize_attribute_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    n = name.strip()
    if n in TWOCBOM_ATTRIBUTE_ALIASES:
        return TWOCBOM_ATTRIBUTE_ALIASES[n]
    return TWOCBOM_ATTRIBUTE_ALIASES.get(n.lower(), n)


@dataclass
class Reconciliation:
    tool_a: str
    tool_b: str
    attribute: Optional[str]
    category: dict
    category_used: dict
    backoff_steps: int
    tier: str
    p_a_better: float
    relevance: float
    confidence: float
    decision: str
    preferred: Optional[str]
    weights: dict
    support: dict
    versions: dict
    explanation: list = field(default_factory=list)
    value_evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "toolA": self.tool_a, "toolB": self.tool_b, "attribute": self.attribute,
            "category": self.category, "categoryUsed": self.category_used, "backoffSteps": self.backoff_steps,
            "tier": self.tier, "pABetter": round(self.p_a_better, 4), "relevance": round(self.relevance, 4),
            "confidence": round(self.confidence, 4), "decision": self.decision, "preferred": self.preferred,
            "weights": {k: round(v, 4) for k, v in self.weights.items()}, "support": self.support,
            "toolVersions": self.versions, "scoringModelVersion": SCORING_MODEL_VERSION,
            "explanation": self.explanation, "valueEvidence": self.value_evidence,
        }


class Scorecard:
    """A scorecard document (``scorecard.json`` with ledger, or the compact ``priors.json``)."""

    def __init__(self, doc: dict):
        self.doc = doc
        self.tools: dict = doc.get("tools") or {}
        self.baseline: dict = doc.get("baseline") or {}
        self.scores: dict = doc.get("scores") or {}
        self.pairwise: dict = doc.get("pairwise") or {}
        cfg = (doc.get("run") or {}).get("config") or {}
        self.scoring_cfg: dict = {**DEFAULT_CONFIG["scoring"], **(cfg.get("scoring") or {})}
        self.weights: dict = {**DEFAULT_CONFIG["scoring"]["weights"], **(self.scoring_cfg.get("weights") or {})}
        self.backoff_order = tuple(self.scoring_cfg.get("backoff_order") or DEFAULT_BACKOFF_ORDER)
        self._gt_rows: dict[str, list] = {}
        self._fp_rows: dict[str, list] = {}
        for row in doc.get("ledger") or []:
            if row.get("kind") == "fp":
                self._fp_rows.setdefault(row["tool"], []).append(row)
            else:
                self._gt_rows.setdefault(row["tool"], []).append(row)
        self._cache: dict = {}

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: Union[str, Path]) -> "Scorecard":
        p = Path(path)
        if p.is_dir():
            for name in ("scorecard.json", "priors.json"):
                if (p / name).is_file():
                    p = p / name
                    break
            else:
                raise FileNotFoundError(f"{path}: no scorecard.json or priors.json")
        with open(p, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    @property
    def has_ledger(self) -> bool:
        return bool(self._gt_rows)

    def tool_ids(self) -> list:
        return sorted(set(self.tools) | set(self.scores) | set(self._gt_rows))

    def version_of(self, tool: str) -> Optional[str]:
        t = self.tools.get(tool) or {}
        return t.get("version") or t.get("tag")

    def gt_rows(self, tool: str) -> list:
        return self._gt_rows.get(tool, [])

    def fp_rows(self, tool: str) -> list:
        return self._fp_rows.get(tool, [])

    # ------------------------------------------------------------------ scores
    def overall(self, tool: str) -> Optional[dict]:
        return self.category_score(tool, {})

    def category_score(self, tool: str, facets: dict) -> Optional[dict]:
        key = (tool, category_key(facets))
        if key in self._cache:
            return self._cache[key]
        result = None
        if self.has_ledger:
            rows = [r for r in self.gt_rows(tool) if row_matches(r, facets)]
            fps = [r for r in self.fp_rows(tool) if fp_matches(r, facets)]
            prior = None
            if facets:
                ov = self.overall(tool)
                prior = ov.get("score") if ov else None
            result = aggregate(rows, fps, self.weights, prior_score=prior,
                               shrinkage_k=float(self.scoring_cfg.get("shrinkage_prior_weight", 5)))
        else:
            tool_scores = self.scores.get(tool) or {}
            if not facets:
                result = tool_scores.get("overall")
            else:
                result = (tool_scores.get("byCategory") or {}).get(category_key(facets))
        self._cache[key] = result
        return result

    def head_to_head(self, tool_a: str, tool_b: str, facets: dict) -> dict:
        if self.has_ledger:
            return head_to_head(self.gt_rows(tool_a), self.gt_rows(tool_b), facets)
        key, swapped = pair_key(tool_a, tool_b)
        table = (self.pairwise.get(key) or {}).get(category_key(facets)) or {}
        return {attr: (swap_counts(c) if swapped else c) for attr, c in table.items()}

    # ------------------------------------------------------------------ backoff
    def backoff_chain(self, facets: dict) -> list:
        chain = [dict(facets)]
        current = dict(facets)
        for facet in self.backoff_order:
            if facet in current:
                current = {k: v for k, v in current.items() if k != facet}
                chain.append(dict(current))
        # facets not in the backoff order are dropped last, together
        if current:
            chain.append({})
        return chain

    # ------------------------------------------------------------------ reconciliation
    def reconcile(self, tool_a: str, tool_b: str, category: Union[dict, str, None] = None,
                  attribute: Optional[str] = None, value_a=None, value_b=None) -> Reconciliation:
        facets = parse_category(category) if isinstance(category, str) else dict(category or {})
        attribute = normalize_attribute_name(attribute)
        cfg = self.scoring_cfg
        min_support = int(cfg.get("min_support", 5))
        min_h2h = int(cfg.get("min_support_head_to_head", 3))
        decay = float(cfg.get("backoff_relevance_decay", 0.15))
        undecided_below = float(cfg.get("undecided_below", 0.6))
        chain = self.backoff_chain(facets)
        explanation: list[str] = []
        versions = {tool_a: self.version_of(tool_a), tool_b: self.version_of(tool_b)}

        def finish(tier: str, p: float, used: dict, steps: int, support: dict) -> Reconciliation:
            relevance = 1.0 / (1.0 + decay * steps)
            p_adj = 0.5 + (p - 0.5) * relevance
            confidence = max(p_adj, 1.0 - p_adj)
            if p_adj >= undecided_below:
                decision, preferred = "prefer-a", tool_a
            elif (1.0 - p_adj) >= undecided_below:
                decision, preferred = "prefer-b", tool_b
            else:
                decision, preferred = "undecided", None
            if steps:
                explanation.append(f"backed off {steps} facet(s) from {category_key(facets)} to {category_key(used)}; "
                                   f"relevance {relevance:.2f}")
            explanation.append(f"P({tool_a} more reliable) = {p_adj:.3f} -> {decision}")
            return Reconciliation(tool_a, tool_b, attribute, facets, used, steps, tier, p_adj, relevance, confidence,
                                  decision, preferred, {tool_a: p_adj, tool_b: 1.0 - p_adj}, support, versions,
                                  explanation, self._value_evidence(tool_a, tool_b, facets, attribute, value_a, value_b))

        # missing-vs-present is a completeness question, not a conflict
        a_missing = value_a in (None, "", [], {}) and value_b not in (None, "", [], {}) and value_b is not None
        b_missing = value_b in (None, "", [], {}) and value_a not in (None, "", [], {}) and value_a is not None
        if attribute and (a_missing or b_missing):
            present, other = (tool_b, tool_a) if a_missing else (tool_a, tool_b)
            for steps, used in enumerate(chain):
                corr, n = attribute_evidence([r for r in self.gt_rows(present) if row_matches(r, used)], attribute)
                if n >= min_support or used == {}:
                    a, b = posterior(corr, n)
                    rate = a / (a + b)
                    p = rate if present == tool_a else 1.0 - rate
                    explanation.append(f"{other} reported no value; {present} reports {attribute} correctly "
                                       f"{corr:.1f}/{n} times in {category_key(used)}")
                    return finish("completeness", p, used, steps, {present: {"correct": round(corr, 2), "reported": n}})

        # tier 1: head-to-head
        if attribute or True:
            attr_key = attribute or "*"
            for steps, used in enumerate(chain):
                counts = self.head_to_head(tool_a, tool_b, used).get(attr_key)
                if not counts:
                    continue
                n = counts["aWins"] + counts["bWins"]
                if n >= min_h2h:
                    a, b = posterior(counts["aWins"], n)
                    p = prob_above_half(a, b)
                    explanation.append(f"head-to-head on {attr_key} in {category_key(used)}: {tool_a} right "
                                       f"{counts['aWins']}x, {tool_b} right {counts['bWins']}x, both wrong "
                                       f"{counts['bothWrong']}x, agreed {counts['agree']}x")
                    return finish("head-to-head", p, used, steps, {"disagreements": n, "counts": counts})

        # tier 2: independent attribute correctness
        if attribute:
            for steps, used in enumerate(chain):
                ca, na = attribute_evidence([r for r in self.gt_rows(tool_a) if row_matches(r, used)], attribute)
                cb, nb = attribute_evidence([r for r in self.gt_rows(tool_b) if row_matches(r, used)], attribute)
                if (na >= min_support and nb >= min_support) or (used == {} and (na or nb)):
                    pa = posterior(ca, na)
                    pb = posterior(cb, nb)
                    p = prob_greater(pa[0], pa[1], pb[0], pb[1])
                    explanation.append(f"{attribute} correctness in {category_key(used)}: {tool_a} {ca:.1f}/{na}, "
                                       f"{tool_b} {cb:.1f}/{nb}")
                    return finish("attribute", p, used, steps,
                                  {tool_a: {"correct": round(ca, 2), "reported": na}, tool_b: {"correct": round(cb, 2), "reported": nb}})

        # tier 3 / 4: composite category score, then global
        for steps, used in enumerate(chain):
            sa, sb = self.category_score(tool_a, used), self.category_score(tool_b, used)
            if not sa or not sb:
                continue
            na, nb = sa.get("support", 0), sb.get("support", 0)
            if sa.get("score") is None or sb.get("score") is None:
                continue
            if (na >= min_support and nb >= min_support) or used == {}:
                pa = posterior(sa["score"] * na, na)
                pb = posterior(sb["score"] * nb, nb)
                p = prob_greater(pa[0], pa[1], pb[0], pb[1]) if (na and nb) else 0.5
                tier = "global" if used == {} else "category"
                explanation.append(f"composite score in {category_key(used)}: {tool_a} {sa['score']:.3f} (n={na}), "
                                   f"{tool_b} {sb['score']:.3f} (n={nb})")
                return finish(tier, p, used, steps, {tool_a: {"score": sa["score"], "support": na},
                                                      tool_b: {"score": sb["score"], "support": nb}})
        explanation.append("no evidence for either tool")
        return finish("none", 0.5, {}, len(chain) - 1, {})

    # ------------------------------------------------------------------ value evidence
    def _value_evidence(self, tool_a: str, tool_b: str, facets: dict, attribute: Optional[str], value_a, value_b) -> dict:
        if not attribute or not self.has_ledger:
            return {}
        out = {}
        for tool, value in ((tool_a, value_a), (tool_b, value_b)):
            if value in (None, "", [], {}):
                continue
            target = str(value).strip().lower()
            n = 0
            correct = 0.0
            for r in self.gt_rows(tool):
                if not r.get("detected") or not r.get("scored") or not row_matches(r, facets):
                    continue
                a = (r.get("attributes") or {}).get(attribute)
                if not a or a.get("reported") in (None, "", [], {}):
                    continue
                rep = a["reported"]
                rep_s = json.dumps(rep).lower() if isinstance(rep, (list, dict)) else str(rep).strip().lower()
                if rep_s == target:
                    n += 1
                    correct += float(a.get("correct") or 0.0)
            if n:
                out[tool] = {"value": value, "timesReported": n, "timesCorrect": round(correct, 2)}
        return out

    # ------------------------------------------------------------------ bulk helpers
    def all_category_scores(self, tool: str, combos=FACET_COMBOS) -> dict:
        """Scores for every precomputable category combination with support > 0."""
        rows = self.gt_rows(tool)
        out: dict[str, dict] = {}
        for combo in combos:
            values: set = set()
            if not combo:
                values.add(())
            else:
                for r in rows:
                    vals = []
                    ok = True
                    for f in combo:
                        if f in ("scenario", "library"):
                            lst = r.get("scenarios" if f == "scenario" else "libraries") or []
                            if not lst:
                                ok = False
                                break
                            vals.append(tuple(lst))
                        else:
                            vals.append((r.get(f),))
                    if not ok:
                        continue
                    import itertools
                    for prod in itertools.product(*vals):
                        values.add(prod)
            for prod in sorted(values, key=lambda t: tuple(str(x) for x in t)):
                facets = {f: v for f, v in zip(combo, prod) if v is not None}
                if len(facets) != len(combo):
                    continue
                agg = self.category_score(tool, facets)
                if agg and agg.get("support"):
                    out[category_key(facets)] = agg
        return out
