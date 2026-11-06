from orchestrator.evaluate.ledger import evaluate_case
from orchestrator.evaluate.matcher import match_case
from orchestrator.normalize import read_cbom


def _rows(gt, doc, tool="t"):
    ev = evaluate_case(gt, read_cbom(doc), tool, "1")
    return {r["assetId"]: r for r in ev.rows}, ev.fp_rows, ev


def test_exact_match_by_oid_and_descriptor(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("AES/GCM/NoPadding", ps="256", oid="2.16.840.1.101.3.4.1.46", occurrences=[20])])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["aes-256-gcm"]
    assert r["detected"] and r["matchLevel"] == "oid" and r["identityScore"] == 1.0
    assert not fps


def test_family_only_detection_is_partial_credit_not_false_positive(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("AES", occurrences=[22])])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["aes-256-gcm"]
    assert r["detected"] and r["matchLevel"] == "family" and 0 < r["identityScore"] < 1
    assert not rows["aes-128-cbc"]["detected"]
    assert not fps
    # it reported no parameter set and no mode: completeness suffers, correctness of the rest is intact
    assert r["attributes"]["parameterSetIdentifier"]["reported"] is None
    assert r["attributes"]["mode"]["reported"] is None


def test_location_disambiguates_same_family(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("AES", occurrences=[30])])
    rows, fps, _ = _rows(mini_gt, doc)
    assert rows["aes-128-cbc"]["detected"] and not rows["aes-256-gcm"]["detected"]


def test_one_detection_spanning_two_assets_credits_both(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("AES", occurrences=[22, 30])])
    rows, fps, _ = _rows(mini_gt, doc)
    assert rows["aes-128-cbc"]["detected"] and rows["aes-256-gcm"]["detected"]


def test_wrong_parameter_is_a_correctness_error(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("AES-128-GCM", ps="128", mode="gcm", occurrences=[20])])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["aes-256-gcm"]
    assert r["detected"] and r["matchLevel"] == "partial"
    assert r["attributes"]["parameterSetIdentifier"]["correct"] == 0.0
    assert r["attributes"]["mode"]["correct"] == 1.0


def test_unlocated_detection_goes_to_best_identity_match(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("SHA-384", ps="384")])
    rows, fps, _ = _rows(mini_gt, doc)
    assert rows["sha-384"]["detected"] and rows["sha-384"]["implicit"]
    assert rows["sha-384"]["locations"] is None


def test_lexical_false_positive(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("MD5", occurrences=[50])])
    rows, fps, _ = _rows(mini_gt, doc)
    assert len(fps) == 1 and fps[0]["lexical"] and fps[0]["subtype"] == "hash"


def test_unrelated_detection_is_a_plain_false_positive(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("Camellia-256", occurrences=[20])])
    rows, fps, _ = _rows(mini_gt, doc)
    assert len(fps) == 1 and not fps[0]["lexical"] and fps[0]["family"] == "camellia"


def test_ecdsa_curve_from_size_counts_for_identity_not_curve_attribute(mini_gt, make_cbom, make_algo):
    doc = make_cbom([make_algo("ECDSA", ps="256", occurrences=[40], functions=["sign", "verify"])])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["ecdsa-p256-sha256"]
    assert r["detected"]
    assert r["attributes"]["curve"]["reported"] is None          # the curve was an assumption, not a claim
    assert r["attributes"]["parameterSetIdentifier"]["correct"] == 1.0  # "256" ~ P-256
    assert r["attributes"]["cryptoFunctions"]["correct"] == 1.0


def test_material_matching_uses_algorithm_reference(mini_gt, make_cbom, make_algo):
    doc = make_cbom([
        make_algo("AES-256-GCM", ref="alg", ps="256", mode="gcm", occurrences=[20]),
        {"type": "cryptographic-asset", "bom-ref": "k", "name": "key",
         "cryptoProperties": {"assetType": "related-crypto-material",
                              "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 256, "algorithmRef": "alg"}},
         "evidence": {"occurrences": [{"location": "mini.py", "line": 19}]}},
    ])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["m.gcm-key"]
    assert r["detected"] and r["identityScore"] == 1.0
    assert r["attributes"]["algorithmRef"]["correct"] == 1.0 and r["attributes"]["size"]["correct"] == 1.0


def test_library_matching_by_purl_and_name(mini_gt, make_cbom):
    doc = make_cbom([
        {"type": "library", "bom-ref": "pkg:pypi/cryptography@43.0.1", "name": "cryptography", "version": "43.0.1",
         "purl": "pkg:pypi/cryptography@43.0.1"},
    ])
    rows, fps, _ = _rows(mini_gt, doc)
    r = rows["lib.pyca"]
    assert r["detected"] and r["attributes"]["purl"]["correct"] == 1.0 and r["attributes"]["version"]["correct"] == 0.0
    assert r["locations"] is None


def test_reference_cbom_scores_perfectly(python_gt, fixtures):
    from orchestrator.normalize import read_cbom_file
    cbom = read_cbom_file(fixtures / "baseline-mini" / "Python" / "cbom.cdx.json")
    ev = evaluate_case(python_gt, cbom, "oracle", "ref")
    assert ev.stats["detectedAssets"] == ev.stats["assets"] == 90
    assert not ev.fp_rows
    for r in ev.rows:
        assert r["identityScore"] == 1.0 and r["completeness"] == 1.0 and r["correctness"] == 1.0
        if r["locations"]:
            assert r["locations"]["matched"] == r["locations"]["expected"]


def test_failed_run_is_not_scored_by_default(mini_gt):
    ev = evaluate_case(mini_gt, None, "t", "1", status="failed")
    assert all(not r["scored"] and not r["detected"] for r in ev.rows)
    ev2 = evaluate_case(mini_gt, None, "t", "1", status="failed", treat_failed_as_zero=True)
    assert all(r["scored"] and not r["detected"] for r in ev2.rows)
