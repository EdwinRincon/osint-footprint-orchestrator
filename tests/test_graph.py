from pathlib import Path

from osint_tool.models import Relation, Report, Target
from osint_tool.reporters.graph import (
    AGGREGATE_THRESHOLD,
    GraphReporter,
    _cytoscape_elements,
    _cytoscape_graph_data,
)


def _report(*relations: Relation) -> Report:
    return Report(target=Target(domain="ejemplo.com"), relations=list(relations))


def test_graph_reporter_escribe_solo_recursos_del_grafo_interactivo(
    tmp_path: Path,
) -> None:
    relation = Relation(
        "username:demo_user",
        "profile:https://example.test/demo_user",
        "perfil observado en Example",
        0.5,
        ("WhatsMyName",),
    )

    paths = GraphReporter().write(_report(relation), tmp_path)

    assert paths == [
        tmp_path / "graph.html",
        tmp_path / "graph.js",
        tmp_path / "cytoscape.min.js",
        tmp_path / "CYTOSCAPE-LICENSE.txt",
    ]
    assert not (tmp_path / "graph.dot").exists()
    assert not (tmp_path / "graph.png").exists()
    graph_html = (tmp_path / "graph.html").read_text(encoding="utf-8")
    assert 'src="cytoscape.min.js"' in graph_html
    assert 'id="export">Descargar imagen PNG</button>' in graph_html
    assert 'id="graph-data"' in graph_html
    assert "perfil observado en Example" in graph_html
    assert 'id="export-status" role="status"' in graph_html
    assert "WhatsMyName" in graph_html
    assert (tmp_path / "cytoscape.min.js").stat().st_size > 100_000
    assert "Permission is hereby granted" in (
        tmp_path / "CYTOSCAPE-LICENSE.txt"
    ).read_text(encoding="utf-8")


def test_grafo_sin_relaciones_no_escribe_archivos(tmp_path: Path) -> None:
    assert GraphReporter().write(_report(), tmp_path) == []
    assert list(tmp_path.iterdir()) == []


def test_el_grafo_agrupa_relaciones_repetidas_para_la_vista_inicial() -> None:
    relations = [
        Relation("domain:example.test", f"domain:host-{index}.example.test", "subdominio")
        for index in range(AGGREGATE_THRESHOLD)
    ]
    graph_data = _cytoscape_graph_data(_report(*relations))
    elements = graph_data["elements"]
    group_nodes = [element for element in elements if element["data"].get("is_group")]

    assert graph_data["node_count"] == AGGREGATE_THRESHOLD + 1
    assert graph_data["relation_count"] == AGGREGATE_THRESHOLD
    assert len(group_nodes) == 1
    assert len(graph_data["groups"][group_nodes[0]["data"]["id"]]) == AGGREGATE_THRESHOLD
    assert len(elements) == 3


def test_grafo_marca_solo_los_datos_de_entrada_como_objetivo() -> None:
    relation = Relation(
        "username:demo_user",
        "profile:https://example.test/demo_user",
        "perfil observado en Example",
    )
    report = Report(target=Target(username="demo_user"), relations=[relation])
    elements = _cytoscape_elements(report)
    nodes = {
        element["data"]["id"]: element
        for element in elements
        if "source" not in element["data"]
    }

    assert nodes["username:demo_user"]["classes"] == "target"
    assert "classes" not in nodes["profile:https://example.test/demo_user"]
