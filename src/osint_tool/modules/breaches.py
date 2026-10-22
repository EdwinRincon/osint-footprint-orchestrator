"""Módulo de brechas: consulta la API pública de XposedOrNot (sin clave).

Usa dos endpoints gratuitos, cada uno con su propio límite de uso:
- check-email: nombres de las brechas en las que aparece el email.
- breach-analytics: detalle de cada brecha (sector, año, registros, datos expuestos...).

El detalle es un enriquecimiento: si falla o agota su límite, se conservan los nombres.
Envía el email a un servicio de terceros: usar solo emails propios o ficticios.
Las URLs se configuran en `config.py`.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
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
from osint_tool.registry import ModuleSkipped, register

logger = logging.getLogger(__name__)

SOURCE = "XposedOrNot"
ANALYTICS_SOURCE = "XposedOrNot (analytics)"
DATA_TYPES_SEPARATOR = ";"
SUMMARY_SEPARATOR = " · "
YES = "yes"


@dataclass(frozen=True)
class BreachDetail:
    """Detalle de una brecha según breach-analytics."""

    domain: str = ""
    industry: str = ""
    year: str = ""
    records: int | None = None
    data_types: tuple[str, ...] = ()
    password_risk: str = ""
    verified: bool = False

    def summary(self) -> str:
        """Texto breve y legible para el informe."""
        parts = [
            self.industry,
            self.year,
            f"{self.records} registros" if self.records is not None else "",
            f"datos: {', '.join(self.data_types)}" if self.data_types else "",
            f"riesgo de contraseña: {self.password_risk}" if self.password_risk else "",
            f"dominio: {self.domain}" if self.domain else "",
        ]
        return SUMMARY_SEPARATOR.join(part for part in parts if part)

    def to_raw(self) -> dict[str, Any]:
        """Datos originales aptos para JSON."""
        raw = asdict(self)
        raw["data_types"] = list(self.data_types)
        return raw


def _breach_names(payload: object) -> list[str]:
    """Extrae los nombres de brecha de la respuesta, sin duplicados.

    Con brechas, la API devuelve {"breaches": [["Adobe", ...]]}. Sin ellas
    devuelve {"Error": "Not found"}, que aquí produce una lista vacía.
    """
    if not isinstance(payload, dict):
        return []
    groups = payload.get("breaches")
    if not isinstance(groups, list):
        return []
    names: list[str] = []
    for group in groups:
        candidates = group if isinstance(group, list) else [group]
        names.extend(name.strip() for name in candidates if isinstance(name, str) and name.strip())
    return list(dict.fromkeys(names))


def _text(value: Any) -> str:
    """Texto limpio; los enteros (p. ej. un año) se convierten, lo demás se ignora."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return value.strip() if isinstance(value, str) else ""


def _to_detail(entry: dict[str, Any]) -> BreachDetail:
    records = entry.get("xposed_records")
    data_types = _text(entry.get("xposed_data")).split(DATA_TYPES_SEPARATOR)
    return BreachDetail(
        domain=_text(entry.get("domain")),
        industry=_text(entry.get("industry")),
        year=_text(entry.get("xposed_date")),
        records=records if isinstance(records, int) and not isinstance(records, bool) else None,
        data_types=tuple(item.strip() for item in data_types if item.strip()),
        password_risk=_text(entry.get("password_risk")),
        verified=_text(entry.get("verified")).lower() == YES,
    )


def _breach_details(payload: object) -> dict[str, BreachDetail]:
    """Detalle por nombre de brecha. Una respuesta con todo a null produce un dict vacío."""
    exposed = payload.get("ExposedBreaches") if isinstance(payload, dict) else None
    entries = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    if not isinstance(entries, list):
        return {}
    return {
        _text(entry.get("breach")): _to_detail(entry)
        for entry in entries
        if isinstance(entry, dict) and _text(entry.get("breach"))
    }


def _source_check(source: str, status: SourceCheckStatus, detail: str) -> SourceCheck:
    """Cobertura de la consulta; sin el email ni la URL, solo el resultado."""
    return SourceCheck(source=source, status=status, detail=detail)


@register
class BreachesModule:
    """Indica en qué brechas conocidas aparece un email y qué datos expuso cada una."""

    name = "breaches"
    accepts = frozenset({"email"})

    def __init__(
        self,
        session: requests.Session | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Sesión y configuración se pueden inyectar para probar sin red."""
        self._session = build_session() if session is None else session
        self._settings = load_settings() if settings is None else settings

    def run(self, target: Target) -> ModuleOutput:
        if not target.email:
            return ModuleOutput()

        response = self._session.get(self._build_url(self._settings.breaches_api_url, target.email))

        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise ModuleSkipped("XposedOrNot: límite de uso alcanzado, inténtalo más tarde")
        if response.status_code == HTTPStatus.NOT_FOUND:  # sin datos para este email
            return self._not_found(response.status_code)
        response.raise_for_status()  # otros errores HTTP: los gestiona el servicio

        names = _breach_names(response.json())
        if not names:
            return self._not_found(response.status_code)

        details, analytics_check = self._fetch_details(target.email)
        return ModuleOutput(
            findings=[self._build_finding(name, details.get(name)) for name in names],
            source_checks=[
                _source_check(SOURCE, SourceCheckStatus.FOUND, f"HTTP {response.status_code}"),
                analytics_check,
            ],
        )

    @staticmethod
    def _not_found(http_status: int) -> ModuleOutput:
        check = _source_check(SOURCE, SourceCheckStatus.NOT_FOUND, f"HTTP {http_status}")
        return ModuleOutput(source_checks=[check])

    @staticmethod
    def _build_url(template: str, email: str) -> str:
        return template.format(email=quote(email, safe=""))

    def _fetch_details(self, email: str) -> tuple[dict[str, BreachDetail], SourceCheck]:
        """Enriquecimiento opcional: ningún fallo aquí descarta los nombres ya obtenidos."""
        url = self._build_url(self._settings.breaches_analytics_url, email)
        try:
            response = self._session.get(url)
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                check = _source_check(
                    ANALYTICS_SOURCE, SourceCheckStatus.INCONCLUSIVE, "HTTP 429 (límite de uso)"
                )
                return {}, check
            response.raise_for_status()
            details = _breach_details(response.json())
        except (requests.RequestException, ValueError) as exc:
            logger.info("breach-analytics falló: %s", type(exc).__name__)
            return {}, _source_check(ANALYTICS_SOURCE, SourceCheckStatus.ERROR, type(exc).__name__)

        if not details:
            check = _source_check(
                ANALYTICS_SOURCE, SourceCheckStatus.INCONCLUSIVE, "Sin detalles en la respuesta"
            )
            return {}, check
        return details, _source_check(
            ANALYTICS_SOURCE, SourceCheckStatus.FOUND, f"HTTP {response.status_code}"
        )

    def _build_finding(self, breach_name: str, detail: BreachDetail | None) -> Finding:
        return Finding(
            entity_type="email",
            type="breach",
            value=breach_name,
            source=SOURCE,
            source_url=self._settings.breaches_reference_url,
            raw=detail.to_raw() if detail else {},
            detail=(detail.summary() or None) if detail else None,
        )
