from typing import Any

import pytest
import requests

from osint_tool.config import Settings
from osint_tool.models import SourceCheckStatus, Target
from osint_tool.modules.breaches import BreachesModule
from osint_tool.registry import ModuleSkipped

EMAIL = "ana@ejemplo.com"
TARGET = Target(email=EMAIL)
BASIC_URL = "https://api.xposedornot.com/v1/check-email/ana%40ejemplo.com"
ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email=ana%40ejemplo.com"

BASIC_PAYLOAD = {"breaches": [["Adobe", "LinkedIn"]], "email": EMAIL, "status": "success"}
ADOBE_DETAIL = {
    "breach": "Adobe",
    "domain": "adobe.com",
    "industry": "Technology",
    "xposed_date": "2013",
    "xposed_records": 152445165,
    "xposed_data": "Email addresses;Passwords",
    "password_risk": "hardtocrack",
    "verified": "Yes",
}
ANALYTICS_PAYLOAD = {"ExposedBreaches": {"breaches_details": [ADOBE_DETAIL]}}
ALL_NULL_ANALYTICS = {"BreachMetrics": None, "ExposedBreaches": None, "ExposedPastes": None}


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    """Responde según la URL; una URL inesperada falla el test con KeyError."""

    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self.routes = routes
        self.urls: list[str] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.urls.append(url)
        return self.routes[url]


def _module(
    basic: FakeResponse,
    analytics: FakeResponse | None = None,
    settings: Settings | None = None,
) -> tuple[BreachesModule, FakeSession]:
    routes = {BASIC_URL: basic}
    if analytics is not None:
        routes[ANALYTICS_URL] = analytics
    session = FakeSession(routes)
    # Settings() explícito: el test no depende de variables OSINT_* del entorno.
    module = BreachesModule(session, settings or Settings())  # type: ignore[arg-type]
    return module, session


def _enriched_module() -> tuple[BreachesModule, FakeSession]:
    return _module(FakeResponse(200, BASIC_PAYLOAD), FakeResponse(200, ANALYTICS_PAYLOAD))


def test_devuelve_una_brecha_por_hallazgo() -> None:
    module, _ = _enriched_module()

    findings = module.run(TARGET).findings

    assert [f.value for f in findings] == ["Adobe", "LinkedIn"]
    assert all(f.source == "XposedOrNot" and f.type == "breach" for f in findings)
    assert all(f.entity_type == "email" for f in findings)
    assert all(f.source_url == "https://xposedornot.com/api_doc" for f in findings)


def test_elimina_duplicados() -> None:
    module, _ = _module(
        FakeResponse(200, {"breaches": [["Adobe", "Adobe"]]}),
        FakeResponse(200, ALL_NULL_ANALYTICS),
    )

    assert [f.value for f in module.run(TARGET).findings] == ["Adobe"]


def test_enriquece_cada_brecha_con_su_detalle() -> None:
    module, _ = _enriched_module()

    adobe, linkedin = module.run(TARGET).findings

    assert adobe.detail == (
        "Technology · 2013 · 152445165 registros · datos: Email addresses, Passwords"
        " · riesgo de contraseña: hardtocrack · dominio: adobe.com"
    )
    assert adobe.raw == {
        "domain": "adobe.com",
        "industry": "Technology",
        "year": "2013",
        "records": 152445165,
        "data_types": ["Email addresses", "Passwords"],
        "password_risk": "hardtocrack",
        "verified": True,
    }
    assert (linkedin.detail, linkedin.raw) == (None, {})


def test_con_brechas_ambas_comprobaciones_son_encontradas() -> None:
    module, _ = _enriched_module()

    checks = module.run(TARGET).source_checks

    assert [(c.source, c.status, c.detail) for c in checks] == [
        ("XposedOrNot", SourceCheckStatus.FOUND, "HTTP 200"),
        ("XposedOrNot (analytics)", SourceCheckStatus.FOUND, "HTTP 200"),
    ]


def test_404_es_sin_hallazgos_y_no_consulta_el_detalle() -> None:
    module, session = _module(FakeResponse(404))

    output = module.run(TARGET)

    assert output.findings == []
    assert [(c.status, c.detail) for c in output.source_checks] == [
        (SourceCheckStatus.NOT_FOUND, "HTTP 404")
    ]
    assert session.urls == [BASIC_URL]


def test_cuerpo_not_found_es_sin_hallazgos_y_no_consulta_el_detalle() -> None:
    module, session = _module(FakeResponse(200, {"Error": "Not found", "email": None}))

    output = module.run(TARGET)

    assert output.findings == []
    assert [c.status for c in output.source_checks] == [SourceCheckStatus.NOT_FOUND]
    assert session.urls == [BASIC_URL]


def test_429_omite_el_modulo() -> None:
    module, session = _module(FakeResponse(429))

    with pytest.raises(ModuleSkipped):
        module.run(TARGET)

    assert session.urls == [BASIC_URL]


def test_error_http_se_propaga() -> None:
    module, _ = _module(FakeResponse(500))

    with pytest.raises(requests.HTTPError):
        module.run(TARGET)


def test_respuesta_que_no_es_json_se_propaga_como_value_error() -> None:
    module, _ = _module(FakeResponse(200, ValueError("no es json")))

    with pytest.raises(ValueError):
        module.run(TARGET)


def test_si_el_detalle_agota_su_limite_se_conservan_los_nombres() -> None:
    module, _ = _module(FakeResponse(200, BASIC_PAYLOAD), FakeResponse(429))

    output = module.run(TARGET)

    assert [f.value for f in output.findings] == ["Adobe", "LinkedIn"]
    assert all(f.detail is None for f in output.findings)
    assert [(c.source, c.status) for c in output.source_checks] == [
        ("XposedOrNot", SourceCheckStatus.FOUND),
        ("XposedOrNot (analytics)", SourceCheckStatus.INCONCLUSIVE),
    ]


@pytest.mark.parametrize(
    "analytics, expected_detail",
    [
        (FakeResponse(500), "HTTPError"),
        (FakeResponse(200, ValueError("no es json")), "ValueError"),
    ],
)
def test_si_el_detalle_falla_se_conservan_los_nombres(
    analytics: FakeResponse, expected_detail: str
) -> None:
    module, _ = _module(FakeResponse(200, BASIC_PAYLOAD), analytics)

    output = module.run(TARGET)

    assert [f.value for f in output.findings] == ["Adobe", "LinkedIn"]
    analytics_check = output.source_checks[1]
    assert (analytics_check.status, analytics_check.detail) == (
        SourceCheckStatus.ERROR,
        expected_detail,
    )


def test_detalle_con_todo_a_null_es_inconcluso() -> None:
    module, _ = _module(FakeResponse(200, BASIC_PAYLOAD), FakeResponse(200, ALL_NULL_ANALYTICS))

    output = module.run(TARGET)

    assert [f.value for f in output.findings] == ["Adobe", "LinkedIn"]
    assert output.source_checks[1].status is SourceCheckStatus.INCONCLUSIVE


def test_email_codificado_en_las_dos_urls() -> None:
    module, session = _enriched_module()

    module.run(TARGET)

    assert session.urls == [BASIC_URL, ANALYTICS_URL]


def test_usa_las_urls_de_la_configuracion() -> None:
    settings = Settings(
        breaches_api_url="https://api.test/check/{email}",
        breaches_analytics_url="https://api.test/analytics?e={email}",
        breaches_reference_url="https://doc.test",
    )
    session = FakeSession(
        {
            "https://api.test/check/ana%40ejemplo.com": FakeResponse(200, BASIC_PAYLOAD),
            "https://api.test/analytics?e=ana%40ejemplo.com": FakeResponse(
                200, ANALYTICS_PAYLOAD
            ),
        }
    )
    module = BreachesModule(session, settings)  # type: ignore[arg-type]

    findings = module.run(TARGET).findings

    assert session.urls == [
        "https://api.test/check/ana%40ejemplo.com",
        "https://api.test/analytics?e=ana%40ejemplo.com",
    ]
    assert [f.source_url for f in findings] == ["https://doc.test", "https://doc.test"]


def test_ni_las_comprobaciones_ni_los_detalles_contienen_el_email() -> None:
    module, _ = _enriched_module()

    output = module.run(TARGET)

    assert EMAIL not in repr(output.source_checks)
    assert all(EMAIL not in repr(f.detail) + repr(f.raw) for f in output.findings)


def test_sin_email_no_consulta_nada() -> None:
    module, session = _module(FakeResponse(200, {}))

    output = module.run(Target(domain="ejemplo.com"))

    assert output.findings == []
    assert output.source_checks == []
    assert session.urls == []