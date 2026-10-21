import logging
from pathlib import Path

import pytest

from osint_tool import cli
from osint_tool.models import Finding, ModuleResult, Report, Status, Target
from osint_tool.reporters import reporters_for


def _fake_investigation(target, modules=None):  # type: ignore[no-untyped-def]
    finding = Finding(
        entity_type="domain", type="subdomain", value="a.ejemplo.com", source="Fake"
    )
    return Report(
        target=target,
        results=[
            ModuleResult("domain", Status.OK, [finding]),
            ModuleResult("harvester", Status.SKIPPED, error="theHarvester no está instalado"),
        ],
    )


@pytest.fixture
def salida(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Informes en una carpeta temporal y sin consultar ninguna fuente real."""
    monkeypatch.setenv("OSINT_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(cli, "run_investigation", _fake_investigation)
    return tmp_path


def test_list_modules(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--list-modules"]) == 0
    out = capsys.readouterr().out
    for name in ("breaches", "domain", "harvester", "phone", "usernames"):
        assert name in out


def test_sin_datos_de_entrada_falla(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
    assert "al menos un dato" in capsys.readouterr().err


def test_dato_invalido_falla(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--email", "no-es-un-email"])
    assert exc.value.code == 2
    assert "email no válido" in capsys.readouterr().err


def test_modulo_desconocido_falla(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--domain", "ejemplo.com", "--modules", "nope"])
    assert exc.value.code == 2
    assert "nope" in capsys.readouterr().err


def test_ejecucion_con_formato_json(salida: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--domain", "ejemplo.com", "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert "skipped" in out
    assert "theHarvester no está instalado" in out
    assert "report.json" in out
    assert len(list(salida.glob("*/report.json"))) == 1
    assert list(salida.glob("*/report.html")) == []


def test_ejecucion_con_formato_html_incluye_grafo(salida: Path) -> None:
    assert cli.main(["--domain", "ejemplo.com", "--format", "html"]) == 0
    assert len(list(salida.glob("*/report.html"))) == 1
    assert len(list(salida.glob("*/graph.dot"))) == 1


def test_formato_desconocido() -> None:
    with pytest.raises(ValueError):
        reporters_for("pdf")


def test_resumen_muestra_estado_y_detalle() -> None:
    report = _fake_investigation(Target(domain="ejemplo.com"))
    text = cli.format_summary(report, Path("reports/x"), [Path("reports/x/report.json")])
    assert "domain=ejemplo.com" in text
    assert "skipped" in text
    assert "theHarvester no está instalado" in text
    assert "report.json" in text

def test_urllib3_no_registra_urls_completas() -> None:
    cli.main(["--list-modules"])
    assert logging.getLogger("urllib3").level == logging.ERROR