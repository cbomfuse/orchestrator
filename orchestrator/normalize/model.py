"""The format-agnostic detection model every CBOM is lifted to before evaluation."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from .lexicon import Descriptor

ASSET_TYPES = ("algorithm", "related-crypto-material", "certificate", "protocol", "library", "unknown")


@dataclass
class Occurrence:
    file: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    offset: Optional[int] = None
    symbol: Optional[str] = None
    context: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Detection:
    """One component reported by a tool, with its attributes normalised to CycloneDX 1.6 names."""
    ref: str
    asset_type: str
    name: str
    attrs: dict = field(default_factory=dict)
    oid: Optional[str] = None
    occurrences: list = field(default_factory=list)
    confidence: Optional[float] = None
    descriptor: Optional[Descriptor] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ref": self.ref,
            "assetType": self.asset_type,
            "name": self.name,
            "oid": self.oid,
            "attrs": self.attrs,
            "occurrences": [o.to_dict() for o in self.occurrences],
            "confidence": self.confidence,
            "descriptor": self.descriptor.to_dict() if self.descriptor else None,
        }


@dataclass
class ToolMetadata:
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    tools: list = field(default_factory=list)
    bom_format: Optional[str] = None
    spec_version: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NormalizedCBOM:
    path: str
    format: str                      # cyclonedx | ibm-cbom
    metadata: ToolMetadata
    detections: list
    warnings: list = field(default_factory=list)

    def by_type(self, asset_type: str) -> list:
        return [d for d in self.detections if d.asset_type == asset_type]

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for d in self.detections:
            counts[d.asset_type] = counts.get(d.asset_type, 0) + 1
        return {"format": self.format, "specVersion": self.metadata.spec_version, "tool": self.metadata.tool_name,
                "toolVersion": self.metadata.tool_version, "detections": len(self.detections), "byType": counts}
