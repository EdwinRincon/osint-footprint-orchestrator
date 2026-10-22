import json

import pytest
import requests

from osint_tool import registry
from osint_tool.external_errors import ExternalToolError
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Status,
    Target,
)
from osint_tool.registry import ModuleSkipped
from osint_tool.service import NO_MODULES_NOTE, run_investigation

TARGET = Target(domain="ejemplo.com")
PRIVATE_EMAIL = "persona.privada@ejemplo.com"


class OkModule:
    name = "ok"
    accepts = frozenset({"domain"})

    def run(self, target):
        return [
            Finding(entity_type="domain", type="subdomain", value="a.ejemplo.com", source="Fake")
        ]


class SkippedModule:
    name = "skipped"
    accepts = frozenset({"domain"})

    def run(self, target):
        raise ModuleSkipped("sin clave")


class FailingModule:
    name = "failing"
    accepts = frozenset({"domain"})

    def run(self, target):
        raise requests.ConnectionError("caido")


class LeakyModule:
    name = "leaky"
    accepts = frozenset({"domain"})

    def run(self, target):
        raise requests.ConnectionError(f"fallo en https://api.test/check/{PRIVATE_EMAIL}")


class BuggyModule:
    name = "buggy"
    accepts = frozenset({"domain"})

    def run(self, target):
        raise TypeError("error de programacion con datos sensibles")


class ExternalToolFailureModule:
    name = "external-tool-failure"
    accepts = frozenset({"domain"})

    def run(self, target):
        raise ExternalToolError("herramienta agotó el timeout")


class SourceCheckModule:
    name = "source-check"
    accepts = frozenset({"domain"})

    def run(self, target):
        return ModuleOutput(
            findings=[],
            source_checks=[
                SourceCheck(
                    source="Fake",
                    status=SourceCheckStatus.INCONCLUSIVE,
                    detail="sin respuesta",
                )
            ],
        )


def test_modulo_ok_con_hallazgos_y_relaciones() -> None:
    report = run_investigation(TARGET, [OkModule()])
    result = report.results[0]
    assert result.status is Status.OK
    assert result.error is None
    assert result.duration >= 0
    assert [f.value for f in report.findings] == ["a.ejemplo.com"]
    assert [(r.source, r.target) for r in report.relations] == [
        ("domain:ejemplo.com", "domain:a.ejemplo.com")
    ]


def test_modulo_omitido() -> None:
    result = run_investigation(TARGET, [SkippedModule()]).results[0]
    assert result.status is Status.SKIPPED
    assert result.error == "sin clave"
    assert result.findings == []


def test_un_fallo_esperado_no_tumba_a_los_demas() -> None:
    report = run_investigation(TARGET, [FailingModule(), OkModule()])
    assert [r.status for r in report.results] == [Status.ERROR, Status.OK]
    assert "ConnectionError" in (report.results[0].error or "")
    assert len(report.findings) == 1


def test_fallo_de_herramienta_externa_conserva_el_error_de_dominio() -> None:
    result = run_investigation(TARGET, [ExternalToolFailureModule()]).results[0]
    assert result.status is Status.ERROR
    assert result.error == "herramienta agotó el timeout"


def test_output_conserva_comprobaciones_de_fuente() -> None:
    result = run_investigation(TARGET, [SourceCheckModule()]).results[0]
    assert result.status is Status.OK
    assert len(result.source_checks) == 1
    check = result.source_checks[0]
    assert (check.source, check.status, check.detail) == (
        "Fake",
        SourceCheckStatus.INCONCLUSIVE,
        "sin respuesta",
    )


def test_un_error_inesperado_se_registra_sin_tumbar_a_los_demas() -> None:
    report = run_investigation(TARGET, [BuggyModule(), OkModule()])
    assert [r.status for r in report.results] == [Status.ERROR, Status.OK]
    assert report.results[0].error == "Error inesperado (TypeError)"
    assert len(report.findings) == 1


def test_el_informe_no_filtra_datos_de_la_consulta(caplog: pytest.LogCaptureFixture) -> None:
    report = run_investigation(TARGET, [LeakyModule(), BuggyModule()])
    serialized = json.dumps(report.to_dict())
    assert PRIVATE_EMAIL not in serialized
    assert "datos sensibles" not in serialized
    assert PRIVATE_EMAIL not in caplog.text
    assert "datos sensibles" not in caplog.text
    assert report.results[0].error == "ConnectionError"


def test_sin_modulos_devuelve_informe_vacio_con_aviso() -> None:
    report = run_investigation(TARGET, [])
    assert report.results == []
    assert report.relations == []
    assert report.notes == [NO_MODULES_NOTE]


def test_con_modulos_no_hay_avisos() -> None:
    assert run_investigation(TARGET, [OkModule()]).notes == []


def test_usa_el_registro_si_no_se_pasan_modulos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_REGISTRY", {})
    registry.register(OkModule)
    report = run_investigation(TARGET)
    assert [r.name for r in report.results] == ["ok"]


def test_el_informe_se_serializa_a_json() -> None:
    report = run_investigation(TARGET, [OkModule(), SkippedModule()])
    data = json.loads(json.dumps(report.to_dict()))
    assert [r["status"] for r in data["results"]] == ["ok", "skipped"]
    assert data["notes"] == []
