"""Módulo Have I Been Pwned: consulta brechas mediante su API v3."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import requests

from osint_tool.config import Settings, load_settings
from osint_tool.http import build_session
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import register

SOURCE = "Have I Been Pwned"
API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
API_REFERENCE = "https://haveibeenpwned.com/API/v3#BreachesForAccount"


def _findings(payload: Any) -> list[Finding]:
    if not isinstance(payload, list):
        raise ValueError("Respuesta de HIBP no válida.")

    findings: list[Finding] = []
    seen: set[str] = set()
    for breach in payload:
        if not isinstance(breach, dict):
            raise ValueError("Respuesta de HIBP no válida.")
        name = breach.get("Name")
        data_classes = breach.get("DataClasses", [])
        breach_date = breach.get("BreachDate")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(data_classes, list)
            or any(not isinstance(item, str) for item in data_classes)
            or (breach_date is not None and not isinstance(breach_date, str))
        ):
            raise ValueError("Respuesta de HIBP no válida.")

        name = name.strip()
        if name in seen:
            continue
        seen.add(name)
        exposed_data = [item.strip() for item in data_classes if item.strip()]
        details = []
        if breach_date:
            details.append(f"Fecha: {breach_date}")
        if exposed_data:
            details.append(f"Datos expuestos: {', '.join(exposed_data)}")
        findings.append(
            Finding(
                entity_type="email",
                type="breach",
                value=name,
                source=SOURCE,
                raw={"breach_date": breach_date or "", "data_classes": exposed_data},
                source_url=API_REFERENCE,
                detail=" · ".join(details) or None,
            )
        )
    return findings


def _check(status: SourceCheckStatus, detail: str) -> ModuleOutput:
    return ModuleOutput(source_checks=[SourceCheck(SOURCE, status, detail)])


def _http_status_output(status_code: int) -> ModuleOutput | None:
    if status_code == HTTPStatus.NOT_FOUND:
        return _check(SourceCheckStatus.NOT_FOUND, "HTTP 404")
    if status_code == HTTPStatus.TOO_MANY_REQUESTS:
        return _check(SourceCheckStatus.INCONCLUSIVE, "HTTP 429 (límite de uso)")
    if status_code != HTTPStatus.OK:
        return _check(SourceCheckStatus.ERROR, f"HTTP {status_code}")
    return None


def _response_output(response: requests.Response) -> ModuleOutput:
    try:
        findings = _findings(response.json())
    except (requests.RequestException, ValueError) as exc:
        return _check(SourceCheckStatus.ERROR, type(exc).__name__)

    if not findings:
        return _check(SourceCheckStatus.NOT_FOUND, "Sin brechas en la respuesta.")
    return ModuleOutput(
        findings=findings,
        source_checks=[
            SourceCheck(SOURCE, SourceCheckStatus.FOUND, f"{len(findings)} brecha(s).")
        ],
    )


@register
class HibpModule:
    """Busca brechas de un email; la consulta externa requiere clave y selección explícita."""

    name = "hibp"
    requires_network = True
    accepts = frozenset({"email"})
    web_label = "Brechas de Have I Been Pwned"
    web_description = (
        "Envía el correo a Have I Been Pwned, un tercero. Requiere OSINT_HIBP_API_KEY; "
        "sin clave no se consulta la red."
    )

    def __init__(
        self,
        session: requests.Session | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = load_settings() if settings is None else settings
        self._session = build_session(self._settings) if session is None else session

    def run(self, target: Target) -> ModuleOutput:
        if not target.email:
            return ModuleOutput()

        api_key = self._settings.hibp_api_key
        if not api_key or not api_key.strip():
            return _check(
                SourceCheckStatus.NOT_CONFIGURED,
                "API key no configurada (OSINT_HIBP_API_KEY); no se realizó ninguna consulta.",
            )

        url = API_URL.format(email=quote(target.email, safe=""))
        try:
            response = self._session.get(
                url,
                params={"truncateResponse": "false"},
                headers={
                    "Accept": "application/json",
                    "hibp-api-key": api_key.strip(),
                    "User-Agent": self._settings.user_agent,
                },
            )
        except requests.RequestException as exc:
            return _check(SourceCheckStatus.ERROR, type(exc).__name__)

        status_output = _http_status_output(response.status_code)
        return status_output or _response_output(response)
