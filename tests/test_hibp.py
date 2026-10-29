from typing import Any

import pytest
import requests

from osint_tool.config import Settings
from osint_tool.models import SourceCheckStatus, Target
from osint_tool.modules.hibp import API_REFERENCE, API_URL, SOURCE, HibpModule

EMAIL = "ana+test@ejemplo.com"
TARGET = Target(email=EMAIL)
URL = API_URL.format(email="ana%2Btest%40ejemplo.com")
PAYLOAD = [
    {
        "Name": "Adobe",
        "BreachDate": "2013-10-04",
        "DataClasses": ["Email addresses", "Passwords"],
    },
    {
        "Name": "LinkedIn",
        "BreachDate": "2012-05-05",
        "DataClasses": ["Email addresses", "Passwords"],
    },
]


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _module(
    response: FakeResponse | Exception | None = None,
    api_key: str | None = "test-key",
) -> tuple[HibpModule, FakeSession]:
    session = FakeSession(response or FakeResponse(200, PAYLOAD))
    module = HibpModule(
        session,  # type: ignore[arg-type]
        Settings(hibp_api_key=api_key, user_agent="osintbody-test"),
    )
    return module, session


def test_sin_clave_indica_no_configurado_y_no_hace_consultas() -> None:
    module, session = _module(api_key=None)

    output = module.run(TARGET)

    assert output.findings == []
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (
            SourceCheckStatus.NOT_CONFIGURED,
            "API key no configurada (OSINT_HIBP_API_KEY); no se realizó ninguna consulta.",
        )
    ]
    assert session.calls == []


def test_consulta_api_v3_y_normaliza_hallazgos() -> None:
    module, session = _module()

    output = module.run(TARGET)

    assert [finding.value for finding in output.findings] == ["Adobe", "LinkedIn"]
    assert output.findings[0].detail == (
        "Fecha: 2013-10-04 · Datos expuestos: Email addresses, Passwords"
    )
    assert output.findings[0].raw == {
        "breach_date": "2013-10-04",
        "data_classes": ["Email addresses", "Passwords"],
    }
    assert all(finding.source == SOURCE for finding in output.findings)
    assert all(finding.source_url == API_REFERENCE for finding in output.findings)
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (SourceCheckStatus.FOUND, "2 brecha(s).")
    ]
    assert session.calls == [
        (
            URL,
            {
                "params": {"truncateResponse": "false"},
                "headers": {
                    "Accept": "application/json",
                    "hibp-api-key": "test-key",
                    "User-Agent": "osintbody-test",
                },
            },
        )
    ]


@pytest.mark.parametrize(
    ("status_code", "expected_status", "detail"),
    [
        (404, SourceCheckStatus.NOT_FOUND, "HTTP 404"),
        (429, SourceCheckStatus.INCONCLUSIVE, "HTTP 429 (límite de uso)"),
        (403, SourceCheckStatus.ERROR, "HTTP 403"),
        (500, SourceCheckStatus.ERROR, "HTTP 500"),
    ],
)
def test_status_http_se_reporta_como_cobertura(
    status_code: int, expected_status: SourceCheckStatus, detail: str
) -> None:
    module, _ = _module(FakeResponse(status_code))

    output = module.run(TARGET)

    assert output.findings == []
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (expected_status, detail)
    ]


def test_error_de_red_se_reporta_sin_exponer_url() -> None:
    module, _ = _module(requests.Timeout("request URL contains email"))

    output = module.run(TARGET)

    assert output.findings == []
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (SourceCheckStatus.ERROR, "Timeout")
    ]


def test_respuesta_mal_formada_es_error_explicito() -> None:
    module, _ = _module(FakeResponse(200, {"unexpected": "shape"}))

    output = module.run(TARGET)

    assert output.findings == []
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (SourceCheckStatus.ERROR, "ValueError")
    ]


def test_200_sin_brechas_es_no_encontrado() -> None:
    module, _ = _module(FakeResponse(200, []))

    output = module.run(TARGET)

    assert output.findings == []
    assert [(check.status, check.detail) for check in output.source_checks] == [
        (SourceCheckStatus.NOT_FOUND, "Sin brechas en la respuesta.")
    ]
