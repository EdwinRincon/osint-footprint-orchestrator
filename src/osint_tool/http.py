"""Sesión HTTP compartida: User-Agent, timeout por defecto y reintentos limitados."""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from osint_tool.config import Settings, load_settings


class TimeoutSession(requests.Session):
    """`requests.Session` con timeout por defecto.

    `requests` no permite fijar un timeout global, y olvidarlo deja la
    herramienta colgada. Aquí se aplica siempre, salvo que se indique otro.
    """

    def __init__(self, timeout: float) -> None:
        super().__init__()
        self.timeout = timeout

    def request(
        self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any
    ) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return super().request(method, url, *args, **kwargs)


def build_session(settings: Settings | None = None) -> requests.Session:
    """Crea una sesión lista para usar en los módulos.

    Reintenta solo peticiones de lectura (GET/HEAD) ante errores temporales
    y respeta la cabecera `Retry-After` de las APIs con límite de uso.
    """
    settings = settings or load_settings()
    session = TimeoutSession(settings.http_timeout)
    session.headers["User-Agent"] = settings.user_agent

    retry = Retry(
        total=settings.http_retries,
        backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504),  # 429 no se reintenta: lo gestiona el módulo
        allowed_methods=frozenset({"GET", "HEAD"}),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session