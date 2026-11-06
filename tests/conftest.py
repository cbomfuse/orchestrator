import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def mini_gt():
    from orchestrator.baseline import GroundTruth
    return GroundTruth.load(FIXTURES / "mini-gt.json", "Mini")


@pytest.fixture(scope="session")
def python_gt():
    from orchestrator.baseline import GroundTruth
    return GroundTruth.load(FIXTURES / "baseline-mini" / "Python" / "ground-truth.json", "Python")


def cbom_doc(components, tool="testtool", version="1.0", spec="1.6"):
    return {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": tool, "version": version}]}},
            "components": components}


def algo(name, ref=None, primitive=None, ps=None, mode=None, padding=None, curve=None, functions=None, oid=None,
         occurrences=None, file="mini.py"):
    ap = {k: v for k, v in {"primitive": primitive, "parameterSetIdentifier": ps, "mode": mode, "padding": padding,
                            "curve": curve, "cryptoFunctions": functions}.items() if v is not None}
    comp = {"type": "cryptographic-asset", "bom-ref": ref or name, "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap}}
    if oid:
        comp["cryptoProperties"]["oid"] = oid
    if occurrences:
        comp["evidence"] = {"occurrences": [{"location": file, "line": ln} for ln in occurrences]}
    return comp


@pytest.fixture
def make_cbom():
    return cbom_doc


@pytest.fixture
def make_algo():
    return algo
