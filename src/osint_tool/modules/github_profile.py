"""Perfil público de GitHub por username: extrae los identificadores que el perfil declara.

Una sola solicitud a la API por búsqueda. No se visita la web declarada en el perfil.
Los pivotes son pistas para correlacionar, no prueba de que dos cuentas sean la misma persona.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import requests

from osint_tool.accounts import load_account_index
from osint_tool.github_api import API_HEADERS, LOGIN_PATTERN, SOURCE, is_rate_limited
from osint_tool.http import build_session
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.pivots import extract_github
from osint_tool.registry import register

API_URL = "https://api.github.com/users"
PROFILE_CONFIDENCE = 0.5  # la cuenta existe, pero no se sabe a quién pertenece
INVALID_RESPONSE = "Respuesta de GitHub no válida."


def _check(status: SourceCheckStatus, detail: str) -> ModuleOutput:
    return ModuleOutput(source_checks=[SourceCheck(SOURCE, status, detail)])


@register
class GitHubProfileModule:
    """Consulta el perfil público del username y recoge los enlaces que declara."""

    name = "github_profile"
    requires_network = True
    accepts = frozenset({"username"})
    web_label = "Perfil de GitHub por username"
    web_description = (
        "Envía el username a GitHub y recoge los enlaces que el perfil declara (web, Twitter/X, "
        "email público). API anónima: 60 solicitudes/hora; son pistas, no prueba de identidad."
    )
    third_party_recipients = ("GitHub",)

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = build_session() if session is None else session

    def run(self, target: Target) -> ModuleOutput:
        username = target.username
        if not username:
            return ModuleOutput()
        # GitHub es más estricto que la validación genérica: se descarta antes de usar la red.
        if not LOGIN_PATTERN.fullmatch(username):
            return _check(SourceCheckStatus.NOT_FOUND, "Formato no válido para GitHub.")

        response = self._session.get(
            f"{API_URL}/{quote(username, safe='')}", headers=dict(API_HEADERS)
        )
        if is_rate_limited(response.status_code, response.headers):
            return _check(
                SourceCheckStatus.INCONCLUSIVE, "Límite de solicitudes de GitHub alcanzado."
            )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return _check(SourceCheckStatus.NOT_FOUND, "Perfil no encontrado.")
        response.raise_for_status()

        payload = response.json()
        login = payload.get("login") if isinstance(payload, dict) else None
        if not isinstance(login, str) or login.lower() != username.lower():
            raise ValueError(INVALID_RESPONSE)
        return ModuleOutput(
            findings=[self._finding(username, payload)],
            source_checks=[SourceCheck(SOURCE, SourceCheckStatus.FOUND, "Perfil encontrado.")],
        )

    @staticmethod
    def _finding(login: str, payload: dict[str, Any]) -> Finding:
        # Se usa el username tal como se escribió, igual que `usernames`: así ambos módulos
        # producen el mismo nodo `profile:` y se fusionan en el grafo.
        profile_url = f"https://github.com/{quote(login, safe='')}"
        pivots = [pivot.to_dict() for pivot in extract_github(payload, load_account_index())]
        return Finding(
            entity_type="public_profile",
            type="github_profile",
            value=profile_url,
            source=SOURCE,
            confidence=PROFILE_CONFIDENCE,
            raw={"login": login, "pivots": pivots},
            source_url=profile_url,
            detail=(
                f"Perfil público; {len(pivots)} identificadores declarados. "
                "Son pistas, no confirman identidad."
            ),
        )
