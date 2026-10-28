"""Módulo de usernames: comprueba si existe un perfil público en varias redes.

Los sitios salen del dataset comunitario WhatsMyName (CC BY-SA 4.0), con cientos de
redes, que se configura con OSINT_WMN_FILE.
No hay lista de sitios en el código.

Que un username exista en dos redes NO prueba que sea la misma persona, por
eso los hallazgos llevan confianza baja y el correlador los trata como hipótesis.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
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
from osint_tool.pivots import USERNAME_PLACEHOLDER
from osint_tool.registry import ModuleSkipped, register

logger = logging.getLogger(__name__)

PROFILE_CONFIDENCE = 0.5
MAX_WORKERS = 8  # comprobaciones simultáneas
SITE_TIMEOUT = 5.0  # un sitio lento no merece más espera: su resultado sería inconcluso
DEFAULT_FOUND_CODE = 200
DEFAULT_MISSING_CODE = 404
WMN_PLACEHOLDER = "{account}"
NSFW_CATEGORY = "xx NSFW xx"


@dataclass(frozen=True)
class Site:
    """Una red: cómo consultarla y cómo interpretar la respuesta."""

    name: str
    url: str  # plantilla con {username}
    pretty_url: str | None = None  # perfil legible, si `url` es un endpoint de API
    e_code: int = DEFAULT_FOUND_CODE  # código HTTP si la cuenta existe
    e_string: str = ""  # texto que solo aparece si existe (vacío = no se comprueba)
    m_code: int = DEFAULT_MISSING_CODE  # código HTTP si no existe
    m_string: str = ""  # texto que solo aparece si no existe
    strip_chars: str = ""  # caracteres que el sitio no admite en el username


# Usar un valor predeterminado evita que datos mal tipados del dataset rompan la carga completa.
def _code(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


# Los campos no textuales no tienen interpretación segura como regla de respuesta.
def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


# Validar la estructura de raíz evita interpretar un dataset cambiado como una lista vacía.
def _read_wmn_entries(path: Path) -> list[Any]:
    """Lee la lista `sites` del dataset WhatsMyName."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} no es un JSON válido") from exc
    entries = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path.name}: formato no reconocido (falta la lista 'sites')")
    return entries


# Excluir protecciones respeta las condiciones del sitio y evita automatizar barreras de acceso.
def _is_checkable(entry: Any) -> bool:
    """Descarta entradas inválidas, protegidas, NSFW o con POST."""
    if not isinstance(entry, dict) or entry.get("valid") is False:
        return False
    if entry.get("post_body") or entry.get("protection"):
        return False
    return entry.get("cat") != NSFW_CATEGORY


# Exigir plantillas esenciales evita consultas incompletas contra URLs arbitrarias.
def _to_site(entry: dict[str, Any]) -> Site | None:
    """Convierte una entrada WhatsMyName en `Site`; None si le faltan datos esenciales."""
    name, uri = entry.get("name"), entry.get("uri_check")
    if not isinstance(name, str) or not isinstance(uri, str) or WMN_PLACEHOLDER not in uri:
        return None
    pretty = entry.get("uri_pretty")
    return Site(
        name=name,
        url=uri.replace(WMN_PLACEHOLDER, USERNAME_PLACEHOLDER),
        pretty_url=(
            pretty.replace(WMN_PLACEHOLDER, USERNAME_PLACEHOLDER)
            if isinstance(pretty, str)
            else None
        ),
        e_code=_code(entry.get("e_code"), DEFAULT_FOUND_CODE),
        e_string=_text(entry.get("e_string")),
        m_code=_code(entry.get("m_code"), DEFAULT_MISSING_CODE),
        m_string=_text(entry.get("m_string")),
        strip_chars=_text(entry.get("strip_bad_char")),
    )


# Convertir una sola vez el dataset separa la validación de las comprobaciones HTTP.
def load_wmn_sites(path: Path) -> list[Site]:
    """Lee el dataset WhatsMyName y devuelve los sitios que se pueden comprobar.

    Se omiten entradas NSFW, con POST, marcadas como no válidas o con protecciones
    anti-automatización (captcha, Cloudflare...).

    Raises:
        OSError: si el fichero no se puede leer.
        ValueError: si no es un JSON con la lista `sites`.
    """
    candidates = (_to_site(entry) for entry in _read_wmn_entries(path) if _is_checkable(entry))
    sites = [site for site in candidates if site is not None]
    logger.info("Sitios cargados de %s: %d", path.name, len(sites))
    return sites


# Comunicar la ausencia del dataset como estado explícito evita interpretarla como cero perfiles.
def default_sites(settings: Settings) -> list[Site]:
    """Sitios del dataset configurado.

    Raises:
        ModuleSkipped: si no se ha descargado el dataset desde el repositorio oficial.
    """
    if not settings.wmn_file.is_file():
        raise ModuleSkipped(
            "Dataset WhatsMyName no encontrado: descarga wmn-data.json desde "
            "https://github.com/WebBreacher/WhatsMyName o indica su ruta en OSINT_WMN_FILE."
        )
    return load_wmn_sites(settings.wmn_file)


# Mantener la ambigüedad como None evita clasificar bloqueos como cuentas inexistentes.
def _verdict(site: Site, status: int, text: str) -> bool | None:
    """True = existe, False = no existe, None = respuesta no concluyente."""
    if status == site.e_code and (not site.e_string or site.e_string in text):
        return True
    if status == site.m_code and (not site.m_string or site.m_string in text):
        return False
    return None


# Conservar el nombre del sitio permite explicar cobertura sin revelar parámetros de URL.
def _source_check(site: Site, status: SourceCheckStatus, detail: str) -> SourceCheck:
    # Etiquetar con el sitio conserva el origen de cobertura sin exponer la URL consultada.
    return SourceCheck(source=site.name, status=status, detail=detail)


# Incluir el perfil facilita comprobar manualmente que la coincidencia no sea un falso positivo.
def _build_finding(site: Site, safe_username: str, status_code: int) -> Finding:
    # Guardar el perfil legible facilita su verificación manual sin alterar la consulta.
    profile = (site.pretty_url or site.url).replace(USERNAME_PLACEHOLDER, safe_username)
    return Finding(
        entity_type="username",
        type="profile",
        value=profile,
        source=site.name,
        source_url=profile,
        confidence=PROFILE_CONFIDENCE,
        raw={"site": site.name, "status_code": status_code},
    )


# Reducir timeout y reintentos limita el coste acumulado al consultar cientos de sitios.
def _http_session(settings: Settings) -> requests.Session:
    """Sesión sin reintentos y con timeout corto: con cientos de sitios, esperar multiplica."""
    return build_session(
        replace(
            settings,
            http_retries=0,
            http_timeout=min(settings.http_timeout, SITE_TIMEOUT),
        )
    )


@register
class UsernamesModule:
    """Busca un username en perfiles públicos, sin iniciar sesión ni evadir bloqueos."""

    name = "usernames"
    requires_network = True
    accepts = frozenset({"username"})
    web_label = "Perfiles de username"
    web_description = (
        "Comprueba el username en el dataset WhatsMyName; excluye sitios NSFW por defecto "
        "y puede consultar cientos de sitios."
    )

    # La sesión y el conjunto de sitios inyectables permiten pruebas aisladas y reproducibles.
    def __init__(
        self,
        session: requests.Session | None = None,
        sites: Sequence[Site] | None = None,
    ) -> None:
        """Sesión y sitios se pueden inyectar. Sin sitios, se cargan al ejecutar."""
        self._session = _http_session(load_settings()) if session is None else session
        self._sites = sites
        self._progress_callback: Callable[[int, int], None] | None = None

    # Cambiar el callback por ejecución evita conservar referencias de una investigación previa.
    def set_progress_callback(self, callback: Callable[[int, int], None] | None) -> None:
        # El callback se cambia por investigación para no retener estado entre ejecuciones.
        self._progress_callback = callback

    # Acotar concurrencia y preservar el orden produce progreso útil e informes deterministas.
    def run(self, target: Target) -> ModuleOutput:
        if not target.username:
            return ModuleOutput()

        # Carga diferida: si el dataset falta o falla, el estado queda en el informe del módulo.
        sites = self._sites if self._sites is not None else default_sites(load_settings())
        # Las respuestas llegan en orden variable; guardar por índice mantiene el informe estable.
        outcomes: list[tuple[Finding | None, SourceCheck] | None] = [None] * len(sites)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(self._check, site, target.username): index
                for index, site in enumerate(sites)
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                outcomes[futures[future]] = future.result()
                if self._progress_callback is not None:
                    self._progress_callback(completed, len(sites))

        completed_outcomes = [outcome for outcome in outcomes if outcome is not None]
        findings = [finding for finding, _ in completed_outcomes if finding is not None]
        source_checks = [check for _, check in completed_outcomes]
        self._log_inconclusive(source_checks)
        return ModuleOutput(findings=findings, source_checks=source_checks)

    # Separar los bloqueos evita confundir falta de cobertura con perfiles inexistentes.
    @staticmethod
    def _log_inconclusive(source_checks: Sequence[SourceCheck]) -> None:
        inconclusive = sum(
            check.status is SourceCheckStatus.INCONCLUSIVE for check in source_checks
        )
        if inconclusive:
            logger.warning(
                "%d de %d sitios sin respuesta concluyente (bloqueos, errores o timeouts)",
                inconclusive,
                len(source_checks),
            )

    # No seguir redirecciones ni asumir éxito en respuestas ambiguas evita falsos positivos.
    def _check(self, site: Site, username: str) -> tuple[Finding | None, SourceCheck]:
        """Comprueba un sitio y devuelve hallazgo (si lo hay) más resultado de cobertura."""
        for char in site.strip_chars:
            username = username.replace(char, "")
        safe = quote(username, safe="")  # replace y no format: las URLs pueden llevar llaves
        url = site.url.replace(USERNAME_PLACEHOLDER, safe)

        try:
            # Sin seguir redirecciones: un salto a "login" no significa que exista.
            response = self._session.get(url, allow_redirects=False)
        except requests.RequestException as exc:
            logger.info("%s: fallo de red (%s)", site.name, type(exc).__name__)
            return None, _source_check(site, SourceCheckStatus.ERROR, type(exc).__name__)

        status = response.status_code
        text = response.text if (site.e_string or site.m_string) else ""
        verdict = _verdict(site, status, text)
        detail = f"HTTP {status}"
        if verdict is None:
            # 403, 429, 3xx...: la red nos bloquea o redirige; no es un "no existe".
            logger.info("%s: respuesta no concluyente (%s)", site.name, detail)
            return None, _source_check(site, SourceCheckStatus.INCONCLUSIVE, detail)
        if not verdict:
            return None, _source_check(site, SourceCheckStatus.NOT_FOUND, detail)
        return _build_finding(site, safe, status), _source_check(
            site, SourceCheckStatus.FOUND, detail
        )
