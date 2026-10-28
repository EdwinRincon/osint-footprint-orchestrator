"""Elementos comunes de los módulos que consultan la API pública de GitHub."""

from __future__ import annotations

import re
from collections.abc import Mapping
from http import HTTPStatus

SOURCE = "GitHub"
API_VERSION = "2026-03-10"
API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
}
LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")


# Distinguir el límite de uso de otros 403 evita presentar un bloqueo como un fallo de la fuente.
def is_rate_limited(status_code: int, headers: Mapping[str, str]) -> bool:
    """True si la respuesta indica que se agotó el límite de solicitudes anónimas."""
    return status_code == HTTPStatus.TOO_MANY_REQUESTS or (
        status_code == HTTPStatus.FORBIDDEN and headers.get("X-RateLimit-Remaining") == "0"
    )
