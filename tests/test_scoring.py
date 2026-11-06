import math

import pytest

from orchestrator.evaluate.ledger import evaluate_case
from orchestrator.evaluate.scoring import aggregate, category_key, parse_category, row_matches
from orchestrator.evaluate.stats import betainc, posterior, prob_above_half, prob_greater, wilson_interval
from orchestrator.normalize import read_cbom

W = {"recall": 0.35, "precision": 0.15, "completeness": 0.15, "correctness": 0.25, "locality": 0.10}


def test_beta_functions():
    assert betainc(1, 1, 0.5) == pytest.approx(0.5)
    assert betainc(2, 3, 0.5) == pytest.approx(0.6875)
    assert prob_greater(10, 2, 2, 10) > 0.99
    assert prob_greater(2, 2, 2, 2) == pytest.approx(0.5, abs=1e-6)
    assert prob_above_half(5, 1) == pytest.approx(0.96875)
    assert posterior(8, 10) == (9.0, 3.0)
    lo, hi = wilson_interval(8, 10)
    assert 0.49 < lo < 0.5 and 0.94 < hi < 0.95


def test_category_key_round_trip():
    facets = {"language": "Java", "subtype": "hash", "pqc": True}
    assert category_key(facets) == "language=Java;pqc=True;subtype=hash"
    assert parse_category(category_key(facets)) == facets
    assert parse_category("*") == {} and category_key({}) == "*"


def test_row_matches_list_facets():
    row = {"language": "Go", "scenarios": ["S01", "S02"], "libraries": ["lib.x"]}
    assert row_matches(row, {"scenario": "S02"}) and not row_matches(row, {"scenario": "S03"})
    assert row_matches(row, {"library": "lib.x", "language": "Go"})


def test_aggregate_metrics_from_known_rows(mini_gt, make_cbom, make_algo):
    doc = make_cbom([
        make_algo("AES-256-GCM", ps="256", mode="gcm", occurrences=[20], functions=["encrypt", "decrypt"]),  # exact, 1 of 2 locations
        make_algo("SHA-256", ps="256", occurrences=[10], functions=["digest"]),                               # exact
        make_algo("Camellia", occurrences=[20]),                                                                # false positive
    ])
    ev = evaluate_case(mini_gt, read_cbom(doc), "t", "1")
    agg = aggregate(ev.rows, ev.fp_rows, W)
    assert agg["support"] == 7 and agg["detected"] == 2
    assert agg["recall"] == pytest.approx(2 / 7, abs=1e-4)
    assert agg["truePositives"] == 2 and agg["falsePositives"] == 1
    assert agg["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert agg["locality"] == pytest.approx((0.5 + 1.0) / 2, abs=1e-4)
    assert agg["correctness"] is not None and 0 < agg["correctness"] <= 1
    expected = (W["recall"] * agg["recall"] + W["precision"] * agg["precision"] + W["completeness"] * agg["completeness"]
                + W["correctness"] * agg["correctness"] + W["locality"] * agg["locality"])
    assert agg["score"] == pytest.approx(expected, abs=1e-4)
    assert agg["attributes"]["mode"]["expected"] == 1 and agg["attributes"]["mode"]["correctness"] == 1.0


def test_aggregate_renormalises_weights_without_locality():
    rows = [{"scored": True, "detected": True, "completeness": 1.0, "correctness": 1.0, "locations": None,
             "identityScore": 1.0, "matchLevel": "exact", "attributes": {}, "case": "c", "bestDetection": {"ref": "x"},
             "detectionRefs": ["x"]}]
    agg = aggregate(rows, [], W)
    assert agg["locality"] is None and agg["score"] == pytest.approx(1.0)
