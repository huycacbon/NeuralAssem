"""Normalised graph schema shared by the call graph, CFG and API graph.

Every analyser in this project reduces its output to the same
``{nodes, edges, metadata}`` envelope so the frontend has exactly one shape to
render. New analyses (data-flow, behaviour clustering) plug in by emitting new
``NodeKind``/``EdgeKind`` values rather than a new payload shape.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeKind(StrEnum):
    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    API = "api"
    STRING = "string"
    MODULE = "module"
    BEHAVIOR = "behavior"


class EdgeKind(StrEnum):
    CALL = "CALL"
    JUMP = "JUMP"
    TRUE = "TRUE"
    FALSE = "FALSE"
    FALLTHROUGH = "FALLTHROUGH"
    RETURN = "RETURN"
    REFERENCE = "REFERENCE"
    READ = "READ"
    WRITE = "WRITE"
    DATA_FLOW = "DATA_FLOW"


class CamelModel(BaseModel):
    """Base model emitting camelCase JSON while keeping snake_case in Python."""

    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=lambda field: "".join(
            part if index == 0 else part.capitalize()
            for index, part in enumerate(field.split("_"))
        ),
    )


class Instruction(CamelModel):
    address: str
    mnemonic: str
    operands: str = ""


class GraphNode(CamelModel):
    id: str
    label: str
    kind: NodeKind
    address: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(CamelModel):
    id: str
    source: str
    target: str
    kind: EdgeKind
    metadata: dict[str, Any] = Field(default_factory=dict)


class Graph(CamelModel):
    """The single wire format for all graph endpoints."""

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)
