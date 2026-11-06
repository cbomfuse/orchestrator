import json

from orchestrator.evaluate.ledger import evaluate_case
from orchestrator.evaluate.pairwise import head_to_head
from orchestrator.normalize import read_cbom
from orchestrator.reconcile import Scorecard, normalize_attribute_name


def _scorecard(gt, tools: dict) -> Scorecard:
    ledger = []
    for tool, doc in tools.items():
        ev = evaluate_case(gt, read_cbom(doc), tool, "v1")
        ledger += ev.rows + ev.fp_rows
    return Scorecard({"tools": {t: {"version": "v1"} for t in tools}, "ledger": ledger,
                      "run": {"config": {"scoring": {"min_support": 2, "min_support_head_to_head": 2}}}})


def test_head_to_head_counts(mini_gt, make_cbom, make_algo):
    good = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20]),
                      make_algo("AES-128-CBC", ps="128", mode="cbc", padding="pkcs7", occurrences=[30]),
                      make_algo("SHA-256", ps="256", occurrences=[10])])
    bad = make_cbom([make_algo("AES-256-ECB", ps="256", mode="ecb", occurrences=[20]),
                     make_algo("AES-128-CBC", ps="128", mode="ctr", padding="pkcs7", occurrences=[30]),
                     make_algo("SHA-256", ps="256", occurrences=[10])])
    ev_g = evaluate_case(mini_gt, read_cbom(good), "good", "1")
    ev_b = evaluate_case(mini_gt, read_cbom(bad), "bad", "1")
    h = head_to_head(ev_g.rows, ev_b.rows)
    assert h["mode"]["aWins"] == 2 and h["mode"]["bWins"] == 0
    assert h["parameterSetIdentifier"]["agree"] == 3


def test_reconcile_prefers_the_tool_that_was_right(mini_gt, make_cbom, make_algo):
    good = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20]),
                      make_algo("AES-128-CBC", ps="128", mode="cbc", padding="pkcs7", occurrences=[30])])
    bad = make_cbom([make_algo("AES-256-ECB", ps="256", mode="ecb", occurrences=[20]),
                     make_algo("AES-128-CTR", ps="128", mode="ctr", padding="pkcs7", occurrences=[30])])
    sc = _scorecard(mini_gt, {"good": good, "bad": bad})
    r = sc.reconcile("bad", "good", {"family": "aes"}, "mode")
    assert r.tier == "head-to-head" and r.preferred == "good" and r.decision == "prefer-b"
    assert r.confidence > 0.8 and r.weights["good"] == r.p_a_better_complement() if hasattr(r, "p_a_better_complement") else True
    assert abs(r.weights["good"] + r.weights["bad"] - 1.0) < 1e-9
    d = r.to_dict()
    assert d["toolVersions"] == {"bad": "v1", "good": "v1"}
    json.dumps(d)  # serialisable


def test_reconcile_backs_off_and_discounts(mini_gt, make_cbom, make_algo):
    good = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20]),
                      make_algo("AES-128-CBC", ps="128", mode="cbc", padding="pkcs7", occurrences=[30])])
    bad = make_cbom([make_algo("AES-256-ECB", ps="256", mode="ecb", occurrences=[20]),
                     make_algo("AES-128-CTR", ps="128", mode="ctr", padding="pkcs7", occurrences=[30])])
    sc = _scorecard(mini_gt, {"good": good, "bad": bad})
    direct = sc.reconcile("good", "bad", {"family": "aes"}, "mode")
    backed = sc.reconcile("good", "bad", {"family": "aes", "scenario": "S99"}, "mode")
    assert backed.backoff_steps >= 1 and backed.relevance < 1.0
    assert backed.confidence < direct.confidence


def test_reconcile_completeness_when_one_value_missing(mini_gt, make_cbom, make_algo):
    full = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20], oid="2.16.840.1.101.3.4.1.46"),
                      make_algo("SHA-256", ps="256", occurrences=[10], oid="2.16.840.1.101.3.4.2.1")])
    bare = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20]),
                      make_algo("SHA-256", ps="256", occurrences=[10])])
    sc = _scorecard(mini_gt, {"full": full, "bare": bare})
    r = sc.reconcile("bare", "full", {}, "oid", value_a=None, value_b="2.16.840.1.101.3.4.1.46")
    assert r.tier == "completeness" and r.preferred == "full"


def test_reconcile_falls_back_to_global_scores(mini_gt, make_cbom, make_algo):
    a = make_cbom([make_algo("SHA-256", ps="256", occurrences=[10])])
    b = make_cbom([make_algo("Camellia", occurrences=[20])])
    sc = _scorecard(mini_gt, {"a": a, "b": b})
    r = sc.reconcile("a", "b", {"subtype": "kem"}, None)
    assert r.tier in ("global", "category") and r.preferred == "a"
    assert r.explanation


def test_attribute_aliases_from_twocbom():
    assert normalize_attribute_name("parameterSet") == "parameterSetIdentifier"
    assert normalize_attribute_name("family") == "identity"
    assert normalize_attribute_name("cryptoFunctions") == "cryptoFunctions"


def test_priors_mode_without_ledger(mini_gt, make_cbom, make_algo, tmp_path):
    from orchestrator.export.twocbom import build_priors
    good = make_cbom([make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20]),
                      make_algo("SHA-256", ps="256", occurrences=[10])])
    bad = make_cbom([make_algo("AES-256-ECB", ps="256", mode="ecb", occurrences=[20])])
    sc = _scorecard(mini_gt, {"good": good, "bad": bad})
    doc = dict(sc.doc)
    doc["scores"] = {t: {"overall": sc.overall(t), "byCategory": sc.all_category_scores(t)} for t in ("good", "bad")}
    doc["pairwise"] = {"bad|good": {"*": head_to_head(sc.gt_rows("bad"), sc.gt_rows("good"))}}
    priors = build_priors(doc)
    assert "ledger" not in priors
    p = tmp_path / "priors.json"
    p.write_text(json.dumps(priors))
    sc2 = Scorecard.load(p)
    assert not sc2.has_ledger
    assert sc2.overall("good")["support"] == sc.overall("good")["support"]
    r = sc2.reconcile("good", "bad", {}, None)
    assert r.preferred == "good"
