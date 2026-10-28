"""Genera el grafo interactivo local incluido en el informe HTML."""

from __future__ import annotations

import shutil
from collections import defaultdict
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from osint_tool.correlator import node_id
from osint_tool.models import Relation, Report

AGGREGATE_THRESHOLD = 25
TEMPLATES_DIR = Path(__file__).parent / "templates"
WEB_STATIC_DIR = Path(__file__).parent.parent / "web" / "static"


class CytoscapeGraphData(TypedDict):
    elements: list[dict[str, object]]
    groups: dict[str, list[dict[str, object]]]
    node_count: int
    relation_count: int


class GraphReporter:
    """Escribe los recursos locales necesarios para explorar el grafo interactivo."""

    name = "graph"

    # No generar recursos vacíos evita artefactos que sugieran relaciones inexistentes.
    def write(self, report: Report, directory: Path) -> list[Path]:
        if not report.relations:
            return []

        graph_path = directory / "graph.html"
        environment = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=True,
            undefined=StrictUndefined,
        )
        graph_path.write_text(
            environment.get_template("graph.html").render(
                graph_data=_cytoscape_graph_data(report)
            ),
            encoding="utf-8",
        )
        paths = [
            graph_path,
            directory / "graph.js",
            directory / "cytoscape.min.js",
            directory / "CYTOSCAPE-LICENSE.txt",
        ]
        shutil.copyfile(WEB_STATIC_DIR / "graph.js", paths[1])
        shutil.copyfile(WEB_STATIC_DIR / "vendor" / "cytoscape.min.js", paths[2])
        shutil.copyfile(WEB_STATIC_DIR / "vendor" / "CYTOSCAPE-LICENSE.txt", paths[3])
        return paths


# Mantener este adaptador conserva la forma anterior mientras se comparte el generador nuevo.
def _cytoscape_elements(report: Report) -> list[dict[str, object]]:
    return _cytoscape_graph_data(report)["elements"]


# Construir datos intermedios separa reglas de presentación del renderizado de plantillas.
def _cytoscape_graph_data(report: Report) -> CytoscapeGraphData:
    target_nodes = {
        node_id(kind, value) for kind, value in report.target.to_dict().items()
    }
    nodes: dict[str, dict[str, object]] = {}
    visible_nodes: dict[str, dict[str, object]] = {}
    relation_groups: dict[tuple[str, str], list[tuple[int, Relation]]] = defaultdict(list)

    for relation_index, relation in enumerate(report.relations):
        relation_groups[(relation.source, relation.label)].append((relation_index, relation))

    groups: dict[str, list[dict[str, object]]] = {}
    elements: list[dict[str, object]] = []
    group_index = 0

    # Reutilizar nodos por identificador evita duplicados en relaciones de múltiples fuentes.
    def node_element(identifier: str) -> dict[str, object]:
        if identifier not in nodes:
            kind, _, value = identifier.partition(":")
            label_value = _display_value(kind, value)
            element: dict[str, object] = {
                "data": {
                    "id": identifier,
                    "kind": kind,
                    "value": value,
                    "label": f"{kind.upper()}\n{label_value}",
                    "is_target": identifier in target_nodes,
                }
            }
            if identifier in target_nodes:
                element["classes"] = "target"
            nodes[identifier] = element
        return nodes[identifier]

    # Mantener solo una instancia visible de cada nodo hace el grafo más legible.
    def add_visible_node(identifier: str) -> None:
        visible_nodes.setdefault(identifier, node_element(identifier))

    for (source, label), relations in relation_groups.items():
        if len(relations) >= AGGREGATE_THRESHOLD:
            # Mantén el grafo inicial legible y conserva las aristas individuales para expandirlas.
            group_id = f"osint-group-{group_index}"
            group_index += 1
            group_label = f"{label}\n{len(relations)} entidades"
            group_confidence = sum(
                relation.confidence for _, relation in relations
            ) / len(relations)
            group = {
                "data": {
                    "id": group_id,
                    "kind": "group",
                    "value": group_label,
                    "label": group_label,
                    "is_group": True,
                    "group_count": len(relations),
                    "confidence": group_confidence,
                },
                "classes": "aggregate",
            }
            add_visible_node(source)
            elements.append(group)
            elements.append(
                {
                    "data": {
                        "id": f"{group_id}-edge",
                        "source": source,
                        "target": group_id,
                        "label": f"{label} ({len(relations)} relaciones agrupadas)",
                        "confidence": group_confidence,
                        "evidence": [],
                    }
                }
            )
            groups[group_id] = []
            for relation_index, relation in relations:
                target = node_element(relation.target)
                groups[group_id].append(
                    {
                        "node": target,
                        "edge": {
                            "data": {
                                "id": f"relation-{relation_index}",
                                "source": relation.source,
                                "target": relation.target,
                                "label": relation.label,
                                "confidence": relation.confidence,
                                "evidence": list(relation.evidence),
                            }
                        },
                    }
                )
            continue

        for relation_index, relation in relations:
            add_visible_node(relation.source)
            add_visible_node(relation.target)
            elements.append(
                {
                    "data": {
                        "id": f"relation-{relation_index}",
                        "source": relation.source,
                        "target": relation.target,
                        "label": relation.label,
                        "confidence": relation.confidence,
                        "evidence": list(relation.evidence),
                    }
                }
            )

    return {
        "elements": [*visible_nodes.values(), *elements],
        "groups": groups,
        "node_count": len(nodes),
        "relation_count": len(report.relations),
    }


# Acortar etiquetas limita el solapamiento visual sin alterar el valor guardado en el nodo.
def _display_value(kind: str, value: str) -> str:
    if kind == "profile":
        parsed = urlsplit(value)
        value = f"{parsed.hostname or value}{parsed.path.rstrip('/')}"
    max_length = 26
    return value if len(value) <= max_length else value[: max_length - 1] + "…"
