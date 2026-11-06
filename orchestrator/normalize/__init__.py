"""Format auto-detection and the single entry point used by the evaluator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .cyclonedx import read_cyclonedx
from .ibmcbom import is_ibm_cbom, read_ibm_cbom
from .model import Detection, NormalizedCBOM, Occurrence, ToolMetadata

__all__ = ["read_cbom", "read_cbom_file", "Detection", "NormalizedCBOM", "Occurrence", "ToolMetadata"]


def read_cbom(doc: dict, path: str = "<memory>") -> NormalizedCBOM:
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: CBOM document must be a JSON object")
    if is_ibm_cbom(doc):
        return read_ibm_cbom(doc, path)
    return read_cyclonedx(doc, path)


def read_cbom_file(path: Union[str, Path]) -> NormalizedCBOM:
    p = Path(path)
    with open(p, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return read_cbom(doc, str(p))
