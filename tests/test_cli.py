import json
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


def test_no_args_uses_textual_when_terminal_is_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_run_tui(*, output_format: str) -> None:
        calls.append(output_format)

    monkeypatch.setattr(cli, "_supports_interactive_prompts", lambda: True)
    monkeypatch.setattr(cli, "run_tui", fake_run_tui)
    assert cli.main([]) == 0
    assert calls == ["all"]


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


def test_root_options_output_machine_readable_json(
    salida: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(
        ["--domain", "ejemplo.com", "--format", "json", "--output", "json"]
    ) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["target"] == {"domain": "ejemplo.com"}
    assert data["results"][1]["status"] == "skipped"
    assert "notice" in data
    assert "Investigación completada" not in out
    assert len(list(salida.glob("*/report.json"))) == 1


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


def test_output_csv_contiene_resumen_por_modulo(
    salida: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--domain", "ejemplo.com", "--output", "csv"]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert rows[0] == "module,status,findings,duration_seconds,error"
    assert "domain,ok,1,0.000," in rows
    assert "harvester,skipped,0,0.000,theHarvester no está instalado" in rows


def test_quiet_emite_resumen_compacto(
    salida: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--domain", "ejemplo.com", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "2 módulos · 1 hallazgo · 0 errores · 1 omitido" in out
    assert "Estado por módulo" not in out
    assert "domain=ejemplo.com" not in out


def test_modulo_con_error_devuelve_codigo_uno(
    salida: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failed_investigation(target, modules=None):  # type: ignore[no-untyped-def]
        report = _fake_investigation(target, modules)
        report.results[0].status = Status.ERROR
        report.results[0].error = "falló la consulta"
        return report

    monkeypatch.setattr(cli, "run_investigation", failed_investigation)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--domain", "ejemplo.com", "--output", "json"])
    assert exc.value.code == 1
    assert "falló la consulta" in capsys.readouterr().out


def test_urllib3_no_registra_urls_completas() -> None:
    cli.main(["--list-modules"])
    assert logging.getLogger("urllib3").level == logging.ERROR


def test_scan_subcommand_is_removed() -> None:
    command = cli.typer.main.get_command(cli.app)
    assert not hasattr(command, "commands")
