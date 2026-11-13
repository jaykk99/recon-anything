"""Strict Pydantic input/output schemas for the ReconAnything agent harness.

Every plugin in the deep-lowlevel set (and, by adoption, any plugin
that wants DAG wiring) speaks this contract:

- ``PluginInput`` is what the harness hands a plugin: the target, the
  DAG artifacts produced by earlier layers, and the run budget.
- ``PluginOutput`` is what a plugin must return: findings in the
  strict ``PluginFinding`` shape, the DAG artifacts it produced for
  later layers, and a status/reason. Anything else is rejected by
  ``validate_plugin_output``.
- ``PluginDAG`` is the validated form of ``backend/app/plugin_dag.json``.

Proof discipline is encoded in the schema, not in prose:
``PluginFinding.proof`` is one of ``live_probe`` (a live eth_call
probe from an unfunded stranger confirmed the receipt),
``static`` (verified-source / artifact analysis, needs a live probe
to become a verdict), or ``simulation_only`` (a local fork/fuzz/sim
produced it). A ``simulation_only`` finding can never be
VERIFIED_REAL; the validator caps it at UNVERIFIED.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["low", "medium", "high"]
ProofKind = Literal["live_probe", "static", "simulation_only"]
ReportClass = Literal["candidate", "trigger_only", "unverified"]
PluginStatus = Literal["ok", "skipped", "rate_limited", "error"]
TargetKind = Literal["crypto_wallet", "domain", "url", "file", "contract", "program"]
DAGLayer = Literal[-1, 0, 1, 2, 3]
NodeKind = Literal["plugin", "existing_plugin", "planned_plugin",
                   "harness", "harness_plugin"]


class TargetRef(BaseModel):
    """What the plugin is pointed at. One target per run."""

    kind: TargetKind
    value: str = Field(..., min_length=1, max_length=4096)
    chain: Optional[str] = Field(default=None, max_length=64)
    address: Optional[str] = Field(default=None, max_length=128)

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class DAGArtifact(BaseModel):
    """One named artifact flowing along a DAG edge."""

    name: str = Field(..., min_length=1, max_length=128)
    producer: str = Field(..., min_length=1, max_length=128)
    payload: Dict[str, Any] = Field(default_factory=dict)


class PluginInput(BaseModel):
    """Harness -> plugin. The DAG context carries layer-0/1 artifacts."""

    plugin_id: str = Field(..., min_length=1, max_length=128)
    target: TargetRef
    artifacts: List[DAGArtifact] = Field(default_factory=list)
    dag_context: Dict[str, Any] = Field(default_factory=dict)
    timeout_s: int = Field(default=60, ge=1, le=1800)
    mode: Literal["passive", "active"] = "passive"

    @field_validator("plugin_id")
    @classmethod
    def _plugin_id(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("plugin_id must be [a-z0-9_-]")
        return v


class PluginFinding(BaseModel):
    """One finding. Strict: severity is low/medium/high only, and the
    proof kind decides what the validator may do with it."""

    plugin_id: str = Field(..., min_length=1, max_length=128)
    category: str = Field(..., min_length=1, max_length=64)
    key: str = Field(..., min_length=1, max_length=128)
    value: str = Field(..., min_length=1, max_length=8192)
    source: str = Field(..., min_length=1, max_length=512)
    source_url: Optional[str] = Field(default=None, max_length=2048)
    confidence: int = Field(default=80, ge=0, le=100)
    severity: Severity = "medium"
    proof: ProofKind = "static"
    report_class: ReportClass = "candidate"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    function: Optional[str] = Field(default=None, max_length=256)
    code: Optional[str] = Field(default=None, max_length=8192)
    remediation: Optional[str] = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def _proof_discipline(self) -> "PluginFinding":
        # Simulation-only findings are never candidates for a live
        # verdict: they stay UNVERIFIED by construction.
        if self.proof == "simulation_only" and self.report_class == "candidate":
            raise ValueError(
                "simulation_only findings must use report_class "
                "'unverified' or 'trigger_only', never 'candidate'"
            )
        return self


class PluginOutput(BaseModel):
    """Plugin -> harness. Every plugin run must validate against this."""

    plugin_id: str = Field(..., min_length=1, max_length=128)
    status: PluginStatus = "ok"
    reason: str = Field(default="", max_length=2048)
    findings: List[PluginFinding] = Field(default_factory=list)
    dag_outputs: List[DAGArtifact] = Field(default_factory=list)
    duration_ms: int = Field(default=0, ge=0)

    @field_validator("findings")
    @classmethod
    def _findings_match_plugin(cls, findings: List[PluginFinding]) -> List[PluginFinding]:
        return findings

    @model_validator(mode="after")
    def _ids_match(self) -> "PluginOutput":
        for f in self.findings:
            if f.plugin_id != self.plugin_id:
                raise ValueError(
                    f"finding plugin_id {f.plugin_id!r} != output "
                    f"plugin_id {self.plugin_id!r}"
                )
        for a in self.dag_outputs:
            if a.producer != self.plugin_id:
                raise ValueError(
                    f"dag artifact producer {a.producer!r} != output "
                    f"plugin_id {self.plugin_id!r}"
                )
        return self


class DAGNode(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    kind: NodeKind
    layer: DAGLayer
    file: str = Field(..., min_length=1, max_length=512)
    produces: List[str] = Field(default_factory=list)
    consumes: List[str] = Field(default_factory=list)
    note: Optional[str] = Field(default=None, max_length=2048)
    harness_module: Optional[str] = Field(default=None, max_length=512)


class DAGEdge(BaseModel):
    artifact: str = Field(..., min_length=1, max_length=128)
    from_: str = Field(..., alias="from", min_length=1, max_length=128)
    to: str = Field(..., min_length=1, max_length=128)

    model_config = {"populate_by_name": True}


class PluginDAG(BaseModel):
    """Validated form of backend/app/plugin_dag.json."""

    name: str = Field(..., min_length=1, max_length=128)
    version: str = Field(..., min_length=1, max_length=32)
    description: Optional[str] = Field(default=None, max_length=4096)
    layers: Dict[str, str] = Field(default_factory=dict)
    nodes: List[DAGNode] = Field(default_factory=list)
    edges: List[DAGEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def _edges_reference_nodes(self) -> "PluginDAG":
        ids = {n.id for n in self.nodes}
        for e in self.edges:
            if e.from_ not in ids:
                raise ValueError(f"DAG edge from unknown node {e.from_!r}")
            if e.to not in ids:
                raise ValueError(f"DAG edge to unknown node {e.to!r}")
        return self

    def producers_of(self, artifact: str) -> List[str]:
        return [n.id for n in self.nodes if artifact in n.produces]

    def consumers_of(self, artifact: str) -> List[str]:
        return [n.id for n in self.nodes if artifact in n.consumes]

    def ready(self, plugin_id: str, available: set) -> bool:
        """True when every artifact the plugin consumes is available."""
        node = next((n for n in self.nodes if n.id == plugin_id), None)
        if node is None:
            return False
        return all(a in available for a in node.consumes)


def load_dag(path: Optional[str] = None) -> PluginDAG:
    """Load and validate backend/app/plugin_dag.json."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "plugin_dag.json")
    with open(path, "r", encoding="utf-8") as fh:
        return PluginDAG.model_validate(json.load(fh))


def validate_plugin_output(data: Dict[str, Any]) -> PluginOutput:
    """Validate a raw plugin output dict against the harness contract."""
    return PluginOutput.model_validate(data)


def validate_plugin_input(data: Dict[str, Any]) -> PluginInput:
    """Validate a raw plugin input dict against the harness contract."""
    return PluginInput.model_validate(data)
