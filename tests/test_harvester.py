import json
from collections import defaultdict
from pathlib import Path

import pytest

from osint_tool.cli_runner import CliError, CliResult, ToolNotFoundError
from osint_tool.config import ConfigError
from osint_tool.models import Finding, Target
from osint_tool.modules.harvester import HarvesterModule
from osint_tool.registry import ModuleSkipped

TARGET = Target(domain="ejemplo.com")


def _runner(content: str | None, returncode: int = 0, calls: list[list[str]] | None = None):
    """Ejecutor falso: escribe `content` como si fuera el JSON de theHarvester."""

    def runner(args):
        if calls is not None:
            calls.append(list(args))
        if content is not None:
            base = list(args)[list(args).index("-f") + 1]
            Path(base + ".json").write_text(content, encoding="utf-8")
        return CliResult(returncode, "", "")

    return runner


def _values_by_type(findings: list[Finding]) -> dict[str, list[str]]:
    """Agrupa los valores de los hallazgos por su tipo, conservando el orden."""
    grouped: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        grouped[finding.type].append(finding.value)
    return dict(grouped)


def test_formato_antiguo() -> None:
    payload = {
        "hosts": ["www.ejemplo.com:93.184.216.34", "*.ejemplo.com", "otro.com"],
        "emails": ["info@ejemplo.com", "basura"],
        "ips": ["93.184.216.34", "no-es-ip"],
    }

    findings = HarvesterModule(_runner(json.dumps(payload))).run(TARGET)

    by_type = _values_by_type(findings)
    assert by_type["subdomain"] == ["www.ejemplo.com"]
    assert by_type["harvested_email"] == ["info@ejemplo.com"]
    assert by_type["ip_address"] == ["93.184.216.34"]
    assert all(f.source == "theHarvester" for f in findings)


def test_formato_nuevo() -> None:
    content = json.dumps({"subdomains": ["api.ejemplo.com", "api.ejemplo.com"]})

    findings = HarvesterModule(_runner(content)).run(TARGET)

    assert [f.value for f in findings] == ["api.ejemplo.com"]


def test_descarta_emails_de_otros_dominios() -> None:
    payload = {"emails": ["info@ejemplo.com", "otro@ajeno.org", "dev@mail.ejemplo.com"]}

    findings = HarvesterModule(_runner(json.dumps(payload))).run(TARGET)

    assert _values_by_type(findings)["harvested_email"] == [
        "info@ejemplo.com",
        "dev@mail.ejemplo.com",
    ]


def test_herramienta_ausente_se_omite() -> None:
    def runner(args):
        raise ToolNotFoundError("no está")

    with pytest.raises(ModuleSkipped):
        HarvesterModule(runner).run(TARGET)


def test_el_timeout_de_la_herramienta_se_propaga() -> None:
    def runner(args):
        raise CliError("theHarvester superó el timeout")

    with pytest.raises(CliError, match="timeout"):
        HarvesterModule(runner).run(TARGET)


@pytest.mark.parametrize("content", [None, "", "{no es json", "[]"])
def test_sin_json_legible_es_un_error_aunque_el_codigo_sea_cero(content: str | None) -> None:
    with pytest.raises(CliError, match="JSON legible"):
        HarvesterModule(_runner(content, returncode=0)).run(TARGET)


def test_sin_json_y_codigo_de_error_falla() -> None:
    with pytest.raises(CliError):
        HarvesterModule(_runner(None, returncode=1)).run(TARGET)


def test_comando_con_lista_de_argumentos() -> None:
    calls: list[list[str]] = []

    HarvesterModule(_runner("{}", calls=calls), sources="crtsh,certspotter").run(TARGET)

    command = calls[0]
    assert command[0] == "theHarvester"
    assert command[1:5] == ["-d", "ejemplo.com", "-b", "crtsh,certspotter"]


def test_normaliza_las_fuentes_indicadas() -> None:
    calls: list[list[str]] = []

    HarvesterModule(_runner("{}", calls=calls), sources=" crtsh, certspotter ,").run(TARGET)

    assert calls[0][calls[0].index("-b") + 1] == "crtsh,certspotter"


def test_fuentes_por_defecto_vienen_de_la_configuracion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OSINT_HARVESTER_SOURCES", raising=False)
    calls: list[list[str]] = []

    HarvesterModule(_runner("{}", calls=calls)).run(TARGET)

    assert calls[0][calls[0].index("-b") + 1] == "crtsh,certspotter,hackertarget"


@pytest.mark.parametrize("sources", ["-x", "crtsh;ls", "crtsh urlscan", ",,,"])
def test_rechaza_fuentes_no_validas_sin_ejecutar_nada(sources: str) -> None:
    calls: list[list[str]] = []

    with pytest.raises(ConfigError):
        HarvesterModule(_runner("{}", calls=calls), sources=sources).run(TARGET)

    assert calls == []


def test_rechaza_fuentes_no_validas_del_entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_HARVESTER_SOURCES", "-x")
    calls: list[list[str]] = []

    with pytest.raises(ConfigError):
        HarvesterModule(_runner("{}", calls=calls)).run(TARGET)

    assert calls == []


def test_extrae_las_ip_de_las_entradas_nombre_ip() -> None:
    payload = {
        "hosts": [
            "a.ejemplo.com:1.2.3.4",
            "a.ejemplo.com:5.6.7.8",
            "b.ejemplo.com:2606:4700::1",
            "otro.com:9.9.9.9",
            "*.ejemplo.com",
        ]
    }

    findings = HarvesterModule(_runner(json.dumps(payload))).run(TARGET)

    by_type = _values_by_type(findings)
    assert by_type["subdomain"] == ["a.ejemplo.com", "b.ejemplo.com"]
    assert by_type["ip_address"] == ["1.2.3.4", "5.6.7.8", "2606:4700::1"]


def test_sin_dominio_no_ejecuta_nada() -> None:
    calls: list[list[str]] = []

    findings = HarvesterModule(_runner("{}", calls=calls)).run(Target(email="a@ejemplo.com"))

    assert findings == []
    assert calls == []