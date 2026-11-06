from pathlib import Path

import pytest

from orchestrator.normalize import read_cbom, read_cbom_file


@pytest.mark.parametrize("name,fmt,tool,n", [
    ("cbomkit-java-cdx16.json", "cyclonedx", "IBM/CBOMkit", 7),
    ("cdxgen-python-cdx16.json", "cyclonedx", "@cyclonedx/cdxgen", 9),
    ("cryptobom-forge-cdx16.json", "cyclonedx", "cryptobom-forge", 4),
    ("ibm-prestandard-cbom14.json", "ibm-cbom", "IBM Research cbom-scanner", 5),
    ("pqc-scanner-cdx17.json", "cyclonedx", "cbomkit-theia", 9),
])
def test_reads_every_dialect(fixtures: Path, name, fmt, tool, n):
    norm = read_cbom_file(fixtures / "cboms" / name)
    assert norm.format == fmt
    assert norm.metadata.tool_name == tool
    assert len(norm.detections) == n
    assert not norm.warnings


def test_reference_cbom_round_trip(fixtures: Path):
    norm = read_cbom_file(fixtures / "baseline-mini" / "Python" / "cbom.cdx.json")
    by_type = norm.summary()["byType"]
    assert by_type == {"library": 6, "algorithm": 33, "certificate": 1, "protocol": 1, "related-crypto-material": 49}
    aes = next(d for d in norm.detections if d.name == "AES-256-GCM")
    assert aes.descriptor.canonical() == "aes-256-gcm"
    assert aes.attrs["oid"] == "2.16.840.1.101.3.4.1.46"
    assert aes.occurrences[0].line > 0


def test_ibm_material_and_certificate_translation(fixtures: Path):
    norm = read_cbom_file(fixtures / "cboms" / "ibm-prestandard-cbom14.json")
    cert = next(d for d in norm.detections if d.asset_type == "certificate")
    assert cert.attrs["signatureAlgorithmRef"] == "sha256WithRSAEncryption"
    key = next(d for d in norm.detections if d.asset_type == "related-crypto-material")
    assert key.attrs["type"] == "private-key" and key.attrs["size"] == 2048
    assert key.occurrences and key.occurrences[0].file == "deploy/tls/server.key"


def test_algorithm_ref_resolution(make_cbom, make_algo):
    doc = make_cbom([
        make_algo("AES-256-GCM", ref="alg-1", mode="gcm", ps="256"),
        {"type": "cryptographic-asset", "bom-ref": "key-1", "name": "key",
         "cryptoProperties": {"assetType": "related-crypto-material",
                              "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 256, "algorithmRef": "alg-1"}}},
    ])
    norm = read_cbom(doc)
    key = norm.by_type("related-crypto-material")[0]
    assert key.attrs["algorithmRef"] == "AES-256-GCM"
    assert key.attrs["algorithmRefProps"]["mode"] == "gcm"
