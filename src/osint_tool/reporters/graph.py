"""Grafo de relaciones con Graphviz: escribe graph.dot y, si es posible, graph.png."""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from osint_tool.cli_runner import CliResult, run_cli
from osint_tool.correlator import node_id
from osint_tool.external_errors import ExternalToolError, ToolNotFoundError
from osint_tool.models import Report

logger = logging.getLogger(__name__)

LOW_CONFIDENCE = 0.7  # por debajo, la arista se dibuja discontinua
MAX_LABEL = 40

# tipo de nodo -> (forma, color)
KIND_STYLE: dict[str, tuple[str, str]] = {
    "name": ("ellipse", "#ffe9a8"),
    "email": ("box", "#cfe8ff"),
    "username": ("ellipse", "#d6f5d6"),
    "profile": ("note", "#d6f5d6"),
    "domain": ("box", "#e5d4ff"),
    "phone": ("box", "#ffd6d6"),
    "breach": ("octagon", "#ffb3b3"),
}
DEFAULT_STYLE = ("box", "#eeeeee")
TEMPLATES_DIR = Path(__file__).parent / "templates"
WEB_STATIC_DIR = Path(__file__).parent.parent / "web" / "static"


def _esc(text: str) -> str:
    """Escapa texto para meterlo entre comillas en DOT (evita romper la sintaxis)."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def _quote(text: str) -> str:
    return f'"{_esc(text)}"'


def _shorten(text: str) -> str:
    return text if len(text) <= MAX_LABEL else text[: MAX_LABEL - 1] + "…"


def build_dot(report: Report) -> str:
    """Genera el grafo en formato DOT: nodos del Target y de las relaciones."""
    nodes = {node_id(k, v) for k, v in report.target.to_dict().items()}
    for rel in report.relations:
        nodes.update((rel.source, rel.target))

    lines = [
        "digraph osint {",
        "  rankdir=LR;",
        '  node [fontname="Helvetica" fontsize=10 style=filled];',
        '  edge [fontname="Helvetica" fontsize=9];',
    ]
    for node in sorted(nodes):
        kind, _, value = node.partition(":")
        shape, color = KIND_STYLE.get(kind, DEFAULT_STYLE)
        label = f"{_esc(kind)}\\n{_esc(_shorten(value))}"  # \n de DOT = salto de línea
        lines.append(f'  {_quote(node)} [label="{label}" shape={shape} fillcolor="{color}"];')

    for rel in report.relations:
        label = _esc(rel.label)
        if rel.confidence < 1.0:
            label += f" ({rel.confidence:.0%})"
        style = " style=dashed" if rel.confidence < LOW_CONFIDENCE else ""
        lines.append(f'  {_quote(rel.source)} -> {_quote(rel.target)} [label="{label}"{style}];')

    lines.append("}")
    return "\n".join(lines) + "\n"


class GraphReporter:
    """Escribe `graph.dot` y lo renderiza a `graph.png` si Graphviz está instalado."""

    name = "graph"

    def __init__(self, runner: Callable[[Sequence[str]], CliResult] = run_cli) -> None:
        """El ejecutor se puede inyectar para probar sin Graphviz."""
        self._runner = runner

    def write(self, report: Report, directory: Path) -> list[Path]:
        dot_path = directory / "graph.dot"
        dot_path.write_text(build_dot(report), encoding="utf-8")
        paths = [dot_path]
        if report.relations:
            graph_path = directory / "graph.html"
            environment = Environment(
                loader=FileSystemLoader(TEMPLATES_DIR),
                autoescape=True,
                undefined=StrictUndefined,
            )
            graph_path.write_text(
                environment.get_template("graph.html").render(
                    graph_data=json.dumps(
                        _cytoscape_elements(report), ensure_ascii=False, separators=(",", ":")
                    )
                ),
                encoding="utf-8",
            )
            paths.extend(
                (
                    graph_path,
                    directory / "graph.js",
                    directory / "cytoscape.min.js",
                    directory / "CYTOSCAPE-LICENSE.txt",
                )
            )
            shutil.copyfile(WEB_STATIC_DIR / "graph.js", paths[-3])
            shutil.copyfile(WEB_STATIC_DIR / "vendor" / "cytoscape.min.js", paths[-2])
            shutil.copyfile(WEB_STATIC_DIR / "vendor" / "CYTOSCAPE-LICENSE.txt", paths[-1])

        png_path = directory / "graph.png"

        try:
            result = self._runner(["dot", "-Tpng", str(dot_path), "-o", str(png_path)])
        except ToolNotFoundError:
            logger.warning("Graphviz no está instalado: solo se genera graph.dot")
            return paths
        except ExternalToolError as exc:
            logger.warning("Graphviz falló: %s", exc)
            return paths

        if result.returncode != 0:
            logger.warning("Graphviz terminó con código %s", result.returncode)
            return paths
        paths.append(png_path)
        return paths


def _cytoscape_elements(report: Report) -> list[dict[str, object]]:
    target_nodes = {
        node_id(kind, value) for kind, value in report.target.to_dict().items()
    }
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []
    for relation_index, relation in enumerate(report.relations):
        for identifier in (relation.source, relation.target):
            if identifier in nodes:
                continue
            kind, _, value = identifier.partition(":")
            label_value = _display_value(kind, value)
            nodes[identifier] = {
                "data": {
                    "id": identifier,
                    "kind": kind,
                    "value": value,
                    "label": f"{kind.upper()}\n{label_value}",
                    "is_target": identifier in target_nodes,
                }
            }
            if identifier in target_nodes:
                nodes[identifier]["classes"] = "target"
        edges.append(
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
    return [*nodes.values(), *edges]


def _display_value(kind: str, value: str) -> str:
    if kind == "profile":
        parsed = urlsplit(value)
        value = f"{parsed.hostname or value}{parsed.path.rstrip('/')}"
    max_length = 26
    return value if len(value) <= max_length else value[: max_length - 1] + "…"
