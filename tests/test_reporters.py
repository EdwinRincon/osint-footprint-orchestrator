import json
import stat
from dataclasses import replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from osint_tool.models import (
    Finding,
    ModuleResult,
    Relation,
    Report,
    SourceCheck,
    SourceCheckStatus,
    Status,
    Target,
)
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE, create_report_dir
from osint_tool.reporters.html_reporter import HtmlReporter
from osint_tool.reporters.json_reporter import JsonReporter

FINDING_DETAIL = "Technology · 2013 · 3 registros"


class _TableDepthParser(HTMLParser):
    """Mide cuántas tablas hay anidadas: en un HTML correcto nunca pasa de 1."""

    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.max_depth = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "table":
            self.depth += 1
            self.max_depth = max(self.max_depth, self.depth)

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self.depth -= 1


def _render(directory: Path, report: Report) -> str:
    return HtmlReporter().write(report, directory)[0].read_text(encoding="utf-8")


def _report() -> Report:
    finding = Finding(
        entity_type="domain",
        type="subdomain",
        value="a.ejemplo.com",
        source="Fake",
        retrieved_at=datetime(2026, 10, 13, 18, 45, 0, tzinfo=timezone.utc),
        source_url="https://example.test/source",
        detail=FINDING_DETAIL,
    )
    return Report(
        target=Target(name="Ana Pérez", domain="ejemplo.com"),
        results=[
            ModuleResult(
                name="domain",
                status=Status.OK,
                findings=[finding],
                source_checks=[
                    SourceCheck(
                        source="Example",
                        status=SourceCheckStatus.INCONCLUSIVE,
                        detail="HTTP 429",
                    )
                ],
            ),
            ModuleResult(name="breaches", status=Status.SKIPPED, error="límite de uso"),
        ],
        relations=[
            Relation("domain:ejemplo.com", "domain:a.ejemplo.com", "subdominio", 1.0)
        ],
        created_at=datetime(2026, 10, 13, 18, 45, 0, tzinfo=timezone.utc),
    )


def _report_with_finding(**finding_fields: str | None) -> Report:
    finding = Finding(
        entity_type="domain",
        type="dns_record",
        value="dato",
        source="Fake",
        **finding_fields,
    )
    return Report(
        target=Target(domain="ejemplo.com"),
        results=[ModuleResult(name="domain", status=Status.OK, findings=[finding])],
    )


def test_la_carpeta_usa_la_fecha_del_informe(tmp_path: Path) -> None:
    directory = create_report_dir(tmp_path, _report())
    assert directory.parent == tmp_path
    assert directory.is_dir()
    assert directory.name.startswith("20261013T184500-")


def test_dos_carpetas_del_mismo_informe_son_distintas(tmp_path: Path) -> None:
    report = _report()
    assert create_report_dir(tmp_path, report) != create_report_dir(tmp_path, report)


def test_la_carpeta_se_crea_aunque_falte_el_directorio_de_salida(tmp_path: Path) -> None:
    directory = create_report_dir(tmp_path / "no" / "existe", _report())
    assert directory.is_dir()


def test_write_reports_uses_private_permissions_for_directory_and_all_files(
    tmp_path: Path,
) -> None:
    directory, paths = write_reports(_report(), tmp_path, "all")

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert {path.name for path in paths} == {
        "graph.html",
        "graph.js",
        "cytoscape.min.js",
        "CYTOSCAPE-LICENSE.txt",
        "report.html",
        "report.json",
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)


def test_json_escribe_report_json(tmp_path: Path) -> None:
    paths = JsonReporter().write(_report(), tmp_path)
    assert paths == [tmp_path / "report.json"]
    assert paths[0].is_file()


def test_json_contiene_todo_el_informe(tmp_path: Path) -> None:
    JsonReporter().write(_report(), tmp_path)
    raw = (tmp_path / "report.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["notice"] == LEGAL_NOTICE
    assert data["target"] == {"name": "Ana Pérez", "domain": "ejemplo.com"}
    assert data["notes"] == []
    assert [r["status"] for r in data["results"]] == ["ok", "skipped"]
    assert data["results"][1]["error"] == "límite de uso"
    assert data["results"][0]["findings"][0]["value"] == "a.ejemplo.com"
    assert data["results"][0]["findings"][0]["detail"] == FINDING_DETAIL
    assert data["results"][0]["findings"][0]["source_url"] == "https://example.test/source"
    check = data["results"][0]["source_checks"][0]
    assert check["source"] == "Example"
    assert check["status"] == "inconclusive"
    assert check["detail"] == "HTTP 429"
    assert check["retrieved_at"].endswith("+00:00")
    assert data["relations"][0]["label"] == "subdominio"
    assert "Pérez" in raw  # las tildes no se escapan como \u00e9


def test_json_omite_raw_de_hallazgos_por_defecto(tmp_path: Path) -> None:
    report = _report()
    report.results[0].findings[0] = replace(
        report.results[0].findings[0],
        raw={"response": {"email": "ana@ejemplo.com"}, "api_key": "do-not-export-this"},
    )

    JsonReporter().write(report, tmp_path)

    content = (tmp_path / "report.json").read_text(encoding="utf-8")
    finding = json.loads(content)["results"][0]["findings"][0]
    assert "raw" not in finding
    assert "do-not-export-this" not in content
    assert finding["value"] == "a.ejemplo.com"
    assert report.results[0].findings[0].raw["api_key"] == "do-not-export-this"


def test_json_incluye_los_avisos(tmp_path: Path) -> None:
    report = Report(target=Target(name="Ana Pérez"), notes=["Sin módulos aplicables"])
    JsonReporter().write(report, tmp_path)
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["notes"] == ["Sin módulos aplicables"]


def test_html_contiene_las_secciones_principales(tmp_path: Path) -> None:
    paths = HtmlReporter().write(_report(), tmp_path)
    html = paths[0].read_text(encoding="utf-8")
    assert paths == [tmp_path / "report.html"]
    assert LEGAL_NOTICE in html
    assert "Ana Pérez" in html
    assert "a.ejemplo.com" in html
    assert "límite de uso" in html
    assert "Comprobaciones de domain" in html
    assert "HTTP 429" in html
    assert "inconclusive" in html
    assert "Confianza (heurística)" in html
    assert "Consultado (UTC)" in html
    assert 'href="https://example.test/source"' in html
    assert "2026-10-13T18:45:00+00:00" in html
    assert "verificar con evidencia independiente" in html
    assert 'class="badge skipped"' in html


def test_html_no_incluye_el_grafo_interactivo(tmp_path: Path) -> None:
    (tmp_path / "graph.html").write_text("<p>graph</p>", encoding="utf-8")
    html = _render(tmp_path, _report())

    assert "Grafo interactivo" not in html
    assert "report-graph" not in html
    assert "fullscreen-toggle" not in html
    assert "<p>graph</p>" not in html


def test_html_pliega_tablas_grandes_sin_omitir_datos(tmp_path: Path) -> None:
    report = _report()
    result = report.results[0]
    result.findings *= 101
    result.source_checks *= 101
    report.relations *= 101

    html = _render(tmp_path, report)

    assert "<summary>Mostrar los 101 hallazgos</summary>" in html
    assert "<summary>Mostrar las 101 comprobaciones</summary>" in html
    assert "<summary>Mostrar las 101 relaciones</summary>" in html
    assert html.count(FINDING_DETAIL) == 101


def test_html_muestra_el_detalle_del_hallazgo(tmp_path: Path) -> None:
    html = _render(tmp_path, _report())
    assert "<th>Detalle</th><th>Fuente</th>" in html
    assert FINDING_DETAIL in html


def test_html_sin_detalle_deja_la_celda_vacia(tmp_path: Path) -> None:
    html = _render(tmp_path, _report_with_finding())
    assert "None" not in html


def test_html_escapa_el_detalle(tmp_path: Path) -> None:
    html = _render(tmp_path, _report_with_finding(detail="<script>alert(1)</script>"))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html


def test_html_incluye_la_seccion_de_limitaciones(tmp_path: Path) -> None:
    html = _render(tmp_path, _report())
    assert "<h2>Limitaciones</h2>" in html
    assert "no prueba que pertenezca a la misma persona" in html


def test_html_muestra_los_avisos_escapados(tmp_path: Path) -> None:
    report = Report(target=Target(name="Ana Pérez"), notes=["Aviso <b>de prueba</b>"])
    html = _render(tmp_path, report)
    assert "<h2>Avisos</h2>" in html
    assert "Aviso &lt;b&gt;de prueba&lt;/b&gt;" in html
    assert "<b>de prueba</b>" not in html


def test_html_sin_avisos_no_muestra_la_seccion(tmp_path: Path) -> None:
    html = _render(tmp_path, _report())
    assert "<h2>Avisos</h2>" not in html


def test_html_no_anida_tablas(tmp_path: Path) -> None:
    parser = _TableDepthParser()
    parser.feed(_render(tmp_path, _report()))
    assert parser.max_depth == 1
    assert parser.depth == 0


def test_html_escapa_los_datos_externos(tmp_path: Path) -> None:
    malicious = Finding(
        entity_type="domain",
        type="dns_record",
        value="<script>alert(1)</script>",
        source="DNS",
    )
    report = Report(
        target=Target(domain="ejemplo.com"),
        results=[ModuleResult(name="domain", status=Status.OK, findings=[malicious])],
    )
    html = _render(tmp_path, report)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html


def test_html_no_enlaza_referencias_con_esquema_no_web(tmp_path: Path) -> None:
    html = _render(tmp_path, _report_with_finding(source_url="javascript:alert(1)"))
    assert 'href="javascript:alert(1)"' not in html
    assert "No disponible" in html


def test_html_omite_la_vista_estatica_aunque_exista_una_imagen_antigua(
    tmp_path: Path,
) -> None:
    (tmp_path / "graph.png").write_bytes(b"png")
    html = _render(tmp_path, _report())
    assert "<img" not in html
    assert "Vista estática" not in html