"""Búsqueda acotada de perfiles públicos de GitHub por nombre completo."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from osint_tool.github_api import API_HEADERS, API_VERSION, LOGIN_PATTERN, SOURCE, is_rate_limited
from osint_tool.http import build_session
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import register

API_URL = "https://api.github.com/search/users"
RESULT_LIMIT = 5

__all__ = ["API_URL", "API_VERSION", "RESULT_LIMIT", "SOURCE", "GitHubNameModule"]


@register
class GitHubNameModule:
    """Busca hasta cinco coincidencias por nombre; no afirma que sean la misma persona."""

    name = "github_name"
    requires_network = True
    accepts = frozenset({"name"})
    web_label = "Perfiles de GitHub por nombre"
    web_description = (
        "Busca hasta cinco perfiles públicos por nombre completo. API anónima: "
        "límite de búsqueda de 10 solicitudes por minuto; los resultados son candidatos."
    )
    third_party_recipients = ("GitHub",)

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = build_session() if session is None else session

    def run(self, target: Target) -> ModuleOutput:
        if not target.name:
            return ModuleOutput()

        params: dict[str, str | int] = {
            "q": f"{target.name} in:fullname",
            "per_page": RESULT_LIMIT,
        }
        response = self._session.get(API_URL, params=params, headers=dict(API_HEADERS))
        if is_rate_limited(response.status_code, response.headers):
            return ModuleOutput(
                source_checks=[
                    SourceCheck(
                        SOURCE,
                        SourceCheckStatus.INCONCLUSIVE,
                        "Límite de solicitudes de búsqueda de GitHub alcanzado.",
                    )
                ]
            )
        response.raise_for_status()

        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ValueError("Respuesta de GitHub no válida.")
        users = payload["items"][:RESULT_LIMIT]
        if any(not self._valid_user(user) for user in users):
            raise ValueError("Respuesta de GitHub no válida.")
        findings = [self._finding(user) for user in users]
        if not findings:
            return ModuleOutput(
                source_checks=[
                    SourceCheck(SOURCE, SourceCheckStatus.NOT_FOUND, "Sin coincidencias.")
                ]
            )
        return ModuleOutput(
            findings=findings,
            source_checks=[
                SourceCheck(
                    SOURCE,
                    SourceCheckStatus.FOUND,
                    f"{len(findings)} perfiles candidatos.",
                )
            ],
        )

    @staticmethod
    def _valid_user(user: Any) -> bool:
        return (
            isinstance(user, dict)
            and isinstance(user.get("login"), str)
            and LOGIN_PATTERN.fullmatch(user["login"]) is not None
        )

    @staticmethod
    def _finding(user: dict[str, Any]) -> Finding:
        login = user["login"].strip()
        profile_url = f"https://github.com/{quote(login, safe='')}"
        return Finding(
            entity_type="public_profile",
            type="name_candidate",
            value=login,
            source=SOURCE,
            confidence=0.2,
            raw={"login": login},
            source_url=profile_url,
            detail="Coincidencia de nombre en GitHub; no confirma identidad.",
        )
