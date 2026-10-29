"""Configuración centralizada, leída del entorno.

Es el único lugar del proyecto que accede a `os.environ`. El resto del
código recibe un objeto `Settings`, lo que facilita los tests.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_USER_AGENT = "osint-tool/0.1 (uso educativo)"
DEFAULT_HARVESTER_SOURCES = "crtsh,certspotter,hackertarget"  # fuentes sin clave
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WMN_FILE = PROJECT_ROOT / "data" / "wmn-data.json"
DEFAULT_WMN_UPDATE_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
DEFAULT_BREACHES_API_URL = "https://api.xposedornot.com/v1/check-email/{email}"
DEFAULT_BREACHES_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
DEFAULT_BREACHES_REFERENCE_URL = "https://xposedornot.com/api_doc"

EMAIL_PLACEHOLDER = "{email}"
HTTPS_PREFIX = "https://"
MIN_HTTP_TIMEOUT = 1.0
MIN_HTTP_RETRIES = 0
MIN_CLI_TIMEOUT = 1

_SOURCE_RE = re.compile(r"[A-Za-z0-9_]+")


class ConfigError(ValueError):
    """Valor de configuración inválido en el entorno."""


@dataclass(frozen=True)
class Settings:
    """Ajustes de la aplicación."""

    http_timeout: float = 10.0  # segundos por petición HTTP
    http_retries: int = 2  # reintentos limitados
    cli_timeout: int = 60  # segundos para herramientas externas
    output_dir: Path = Path("reports")
    user_agent: str = DEFAULT_USER_AGENT
    wmn_file: Path = DEFAULT_WMN_FILE  # dataset WhatsMyName con los sitios a comprobar
    wmn_update_url: str = DEFAULT_WMN_UPDATE_URL  # origen oficial del dataset
    harvester_sources: str = DEFAULT_HARVESTER_SOURCES  # fuentes de theHarvester (-b)
    breaches_api_url: str = DEFAULT_BREACHES_API_URL  # nombres de brechas; plantilla con {email}
    breaches_analytics_url: str = DEFAULT_BREACHES_ANALYTICS_URL  # detalle; plantilla con {email}
    breaches_reference_url: str = DEFAULT_BREACHES_REFERENCE_URL  # documentación de la API
    hibp_api_key: str | None = field(default=None, repr=False)  # clave de API Have I Been Pwned


# Un conversor común evita que cada ajuste interprete números de forma distinta.
def _read_number(name: str, default: float, minimum: float) -> float:
    """Lee un número del entorno; falla con un mensaje claro si es inválido."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} debe ser un número, recibido: {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} debe ser >= {minimum}, recibido: {value}")
    return value


# Mantener las rutas como Path simplifica su uso consistente en módulos y reportes.
def _read_path(name: str, default: Path) -> Path:
    """Lee una ruta del entorno; vacía o ausente equivale al valor por defecto."""
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else default


# Rechazar HTTP protege identificadores sensibles que algunas fuentes reciben en la URL.
def _read_https_url(name: str, default: str) -> str:
    """Lee una URL del entorno; solo se admite HTTPS."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    # Estos endpoints pueden recibir identificadores de investigación; no enviarlos en claro.
    if not raw.startswith(HTTPS_PREFIX):
        raise ConfigError(f"{name} debe empezar por {HTTPS_PREFIX}")
    return raw


# Validar la plantilla al cargar evita consultas mal dirigidas por una URL incompleta.
def _read_email_template_url(name: str, default: str) -> str:
    """Lee una plantilla de URL de brechas; debe incluir {email}."""
    url = _read_https_url(name, default)
    # Sin el marcador, una configuración errónea consultaría un endpoint distinto sin avisar.
    if EMAIL_PLACEHOLDER not in url:
        raise ConfigError(f"{name} debe incluir {EMAIL_PLACEHOLDER}")
    return url


# El filtrado de vacíos mantiene tolerantes los separadores repetidos de configuración.
def _split_sources(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


# Validar antes de construir argumentos mantiene los nombres fuera de opciones inesperadas.
def parse_sources(raw: str) -> str:
    """Normaliza una lista de fuentes separadas por comas y valida cada nombre.

    Raises:
        ConfigError: si la lista está vacía o algún nombre no es alfanumérico.
    """
    items = _split_sources(raw)
    if not items:
        raise ConfigError("la lista de fuentes está vacía")
    # Los nombres se insertan como argumento de theHarvester; limitar su alfabeto evita opciones
    # inesperadas.
    for item in items:
        if not _SOURCE_RE.fullmatch(item):
            raise ConfigError(f"nombre de fuente no válido: {item!r}")
    return ",".join(items)


# Añade el nombre de la variable al error para que el usuario pueda corregir el entorno.
def _read_sources(name: str, default: str) -> str:
    """Lee las fuentes del entorno; sin valores, usa las de por defecto."""
    raw = os.environ.get(name, "")
    if not _split_sources(raw):
        return default
    try:
        return parse_sources(raw)
    except ConfigError as exc:
        raise ConfigError(f"{name}: {exc}") from exc


# Un único objeto inmutable hace explícita la configuración compartida entre componentes.
def load_settings() -> Settings:
    """Construye los ajustes a partir de las variables de entorno.

    Variables (todas opcionales):
        OSINT_HTTP_TIMEOUT, OSINT_HTTP_RETRIES, OSINT_CLI_TIMEOUT, OSINT_OUTPUT_DIR,
        OSINT_WMN_FILE, OSINT_WMN_UPDATE_URL,
        OSINT_HARVESTER_SOURCES, OSINT_BREACHES_API_URL, OSINT_BREACHES_ANALYTICS_URL,
        OSINT_BREACHES_REFERENCE_URL, OSINT_HIBP_API_KEY
    """
    defaults = Settings()
    return Settings(
        http_timeout=_read_number("OSINT_HTTP_TIMEOUT", defaults.http_timeout, MIN_HTTP_TIMEOUT),
        http_retries=int(
            _read_number("OSINT_HTTP_RETRIES", defaults.http_retries, MIN_HTTP_RETRIES)
        ),
        cli_timeout=int(_read_number("OSINT_CLI_TIMEOUT", defaults.cli_timeout, MIN_CLI_TIMEOUT)),
        output_dir=_read_path("OSINT_OUTPUT_DIR", defaults.output_dir),
        wmn_file=_read_path("OSINT_WMN_FILE", defaults.wmn_file),
        wmn_update_url=_read_https_url("OSINT_WMN_UPDATE_URL", defaults.wmn_update_url),
        harvester_sources=_read_sources("OSINT_HARVESTER_SOURCES", defaults.harvester_sources),
        breaches_api_url=_read_email_template_url(
            "OSINT_BREACHES_API_URL", defaults.breaches_api_url
        ),
        breaches_analytics_url=_read_email_template_url(
            "OSINT_BREACHES_ANALYTICS_URL", defaults.breaches_analytics_url
        ),
        breaches_reference_url=_read_https_url(
            "OSINT_BREACHES_REFERENCE_URL", defaults.breaches_reference_url
        ),
        hibp_api_key=os.environ.get("OSINT_HIBP_API_KEY", "").strip() or None,
    )