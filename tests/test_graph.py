from pathlib import Path

from osint_tool.cli_runner import CliResult, ToolNotFoundError
from osint_tool.models import Relation, Report, Target
from osint_tool.reporters.graph import GraphReporter, build_dot


def _report(*relations: Relation) -> Report:
    return Report(target=Target(domain="ejemplo.com"), relations=list(relations))


def test_dot_contiene_nodos_y_aristas() -> None:
    rel = Relation("domain:ejemplo.com", "domain:a.ejemplo.com", "subdominio", 1.0)
    dot = build_dot(_report(rel))
    assert dot.startswith("digraph osint {")
    assert '"domain:ejemplo.com" -> "domain:a.ejemplo.com" [label="subdominio"];' in dot


def test_confianza_baja_se_dibuja_discontinua() -> None:
    low = Relation("username:ana", "profile:https://x.test/ana", "perfil en X", 0.5)
    high = Relation("domain:ejemplo.com", "domain:a.ejemplo.com", "subdominio", 1.0)
    edges = [line for line in build_dot(_report(low, high)).splitlines() if "->" in line]
    dashed = [line for line in edges if "style=dashed" in line]
    assert len(dashed) == 1
    assert "perfil en X (50%)" in dashed[0]


def test_los_datos_externos_no_rompen_la_sintaxis_dot() -> None:
    evil = Relation("domain:ejemplo.com", 'dns:x"]; evil [label="y', "registro DNS", 1.0)
    dot = build_dot(_report(evil))
    assert 'evil [label="y' not in dot
    assert '\\"' in dot


def test_sin_relaciones_aparecen_los_nodos_del_target() -> None:
    dot = build_dot(Report(target=Target(email="ana@ejemplo.com")))
    assert '"email:ana@ejemplo.com"' in dot


def test_write_genera_dot_y_png(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(args):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        Path(args[-1]).write_bytes(b"png")
        return CliResult(0, "", "")

    paths = GraphReporter(runner).write(_report(), tmp_path)
    assert paths == [tmp_path / "graph.dot", tmp_path / "graph.png"]
    dot_path = tmp_path / "graph.dot"
    png_path = tmp_path / "graph.png"
    assert paths == [dot_path, png_path]
    assert calls == [["dot", "-Tpng", str(dot_path), "-o", str(png_path)]]


def test_sin_graphviz_solo_se_escribe_el_dot(tmp_path: Path) -> None:
    def runner(args):  # type: ignore[no-untyped-def]
        raise ToolNotFoundError("dot")

    paths = GraphReporter(runner).write(_report(), tmp_path)
    assert paths == [tmp_path / "graph.dot"]
    assert (tmp_path / "graph.dot").is_file()


def test_graphviz_con_error_solo_escribe_el_dot(tmp_path: Path) -> None:
    paths = GraphReporter(lambda args: CliResult(1, "", "error")).write(_report(), tmp_path)
    assert paths == [tmp_path / "graph.dot"]