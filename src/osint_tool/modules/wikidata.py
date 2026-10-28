"""Búsqueda acotada de coincidencias de nombre en la API pública de Wikidata."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

import requests

from osint_tool.http import build_session
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import register

API_URL = "https://www.wikidata.org/w/api.php"
RESULT_LIMIT = 5
LANGUAGE = "es"
SOURCE = "Wikidata"


@register
class WikidataModule:
    """Devuelve hasta cinco coincidencias textuales; no verifica identidades."""

    name = "wikidata"
    requires_network = True
    accepts = frozenset({"name"})
    web_label = "Candidatos de Wikidata"
    web_description = (
        "Envía el nombre a Wikidata y muestra hasta cinco coincidencias públicas; "
        "pueden no ser personas y no confirman identidad."
    )

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = build_session() if session is None else session

    def run(self, target: Target) -> ModuleOutput:
        if not target.name:
            return ModuleOutput()

        params: dict[str, str | int] = {
            "action": "wbsearchentities",
            "format": "json",
            "search": target.name,
            "language": LANGUAGE,
            "uselang": LANGUAGE,
            "type": "item",
            "limit": RESULT_LIMIT,
        }
        response = self._session.get(API_URL, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            return ModuleOutput(
                source_checks=[
                    SourceCheck(
                        SOURCE,
                        SourceCheckStatus.INCONCLUSIVE,
                        "HTTP 429 (límite de uso)",
                    )
                ]
            )
        response.raise_for_status()

        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Respuesta de Wikidata no válida.")
        api_error = payload.get("error")
        if isinstance(api_error, dict):
            if api_error.get("code") in {"ratelimited", "maxlag"}:
                return ModuleOutput(
                    source_checks=[
                        SourceCheck(
                            SOURCE,
                            SourceCheckStatus.INCONCLUSIVE,
                            "Wikidata limitó la consulta.",
                        )
                    ]
                )
            raise ValueError("Wikidata devolvió un error de API.")

        entries = payload.get("search")
        if not isinstance(entries, list):
            raise ValueError("Respuesta de Wikidata no válida.")
        limited_entries = entries[:RESULT_LIMIT]
        if any(not self._valid_entry(entry) for entry in limited_entries):
            raise ValueError("Respuesta de Wikidata no válida.")
        findings = [
            self._finding(entry)
            for entry in limited_entries
        ]
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
                    f"{len(findings)} coincidencias.",
                )
            ],
        )

    @staticmethod
    def _valid_entry(entry: Any) -> bool:
        return (
            isinstance(entry, dict)
            and isinstance(entry.get("id"), str)
            and entry["id"].startswith("Q")
            and entry["id"][1:].isdigit()
            and isinstance(entry.get("label"), str)
            and bool(entry["label"].strip())
        )

    @staticmethod
    def _finding(entry: dict[str, Any]) -> Finding:
        item_id = entry["id"]
        description = entry.get("description")
        detail = "Coincidencia textual de Wikidata; no confirma identidad."
        if isinstance(description, str) and description.strip():
            detail = f"{description.strip()}. {detail}"
        return Finding(
            entity_type="public_entity",
            type="name_candidate",
            value=entry["label"].strip(),
            source=SOURCE,
            confidence=0.2,
            raw={"entity_id": item_id},
            source_url=f"https://www.wikidata.org/wiki/{item_id}",
            detail=detail,
        )
