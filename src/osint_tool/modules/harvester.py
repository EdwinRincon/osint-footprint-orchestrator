"""Módulo theHarvester: integra la herramienta externa por línea de comandos.

Lanza theHarvester con fuentes sin clave, lee el JSON que genera y lo convierte
a `Finding`. Se omite si la herramienta no está instalada.
"""

from __future__ import annotations

import ipaddress
import json
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from osint_tool.cli_runner import CliResult, run_cli
from osint_tool.config import load_settings, parse_sources
from osint_tool.external_errors import ExternalToolError, ToolNotFoundError
from osint_tool.models import Finding, Target
from osint_tool.registry import ModuleSkipped, register
from osint_tool.validation import ValidationError, validate_domain, validate_email

EXECUTABLE = "theHarvester"
SOURCE = "theHarvester"
EMAIL_CONFIDENCE = 0.7  # públicos, pero a menudo antiguos o genéricos
IP_CONFIDENCE = 0.8  # resueltas en algún momento, pueden haber cambiado


def _strings(value: Any) -> list[str]:
    """Lista de textos no vacíos; cualquier otra cosa se ignora."""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _read_json(path: Path) -> dict[str, Any] | None:
    """Lee el JSON generado por la herramienta; None si falta o está corrupto."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _finding(entity_type: str, type_: str, value: str, confidence: float = 1.0) -> Finding:
    return Finding(
        entity_type=entity_type,
        type=type_,
        value=value,
        source=SOURCE,
        confidence=confidence,
    )


def _belongs_to_domain(candidate: str, domain: str) -> bool:
    """True si `candidate` es el dominio o uno de sus subdominios."""
    return candidate == domain or candidate.endswith(f".{domain}")


def _hosts_and_ips(data: dict[str, Any], domain: str) -> tuple[list[str], list[str]]:
    """Subdominios del dominio analizado y las IP que theHarvester les asocia.

    Las entradas son "nombre" o "nombre:ip" (la IP puede ser IPv6). Formato nuevo:
    clave "subdomains"; formato antiguo: clave "hosts".
    """
    raw = _strings(data.get("subdomains")) + _strings(data.get("hosts"))
    hosts: list[str] = []
    ips: list[str] = []
    for item in raw:
        name, _, address = item.partition(":")
        try:
            host = validate_domain(name.removeprefix("*."))  # crt.sh devuelve "*.ejemplo.com"
        except ValidationError:
            continue
        if host == domain or not _belongs_to_domain(host, domain):  # ruido y el propio dominio
            continue
        hosts.append(host)
        if address:
            ips.append(address)
    ips += _strings(data.get("ips"))
    return list(dict.fromkeys(hosts)), ips


def _valid_ips(candidates: list[str]) -> list[str]:
    """IP válidas, normalizadas y sin duplicados."""
    found: list[str] = []
    for item in candidates:
        try:
            found.append(str(ipaddress.ip_address(item)))
        except ValueError:
            continue
    return list(dict.fromkeys(found))


def _emails(data: dict[str, Any], domain: str) -> list[str]:
    """Emails válidos del dominio analizado: los de otros dominios son ruido y datos ajenos."""
    found: list[str] = []
    for item in _strings(data.get("emails")):
        try:
            email = validate_email(item)
        except ValidationError:
            continue
        if _belongs_to_domain(email.rpartition("@")[2], domain):
            found.append(email)
    return list(dict.fromkeys(found))


def _to_findings(data: dict[str, Any], domain: str) -> list[Finding]:
    hosts, raw_ips = _hosts_and_ips(data, domain)
    findings = [_finding("domain", "subdomain", host) for host in hosts]
    findings += [
        _finding("email", "harvested_email", email, EMAIL_CONFIDENCE)
        for email in _emails(data, domain)
    ]
    findings += [_finding("ip", "ip_address", ip, IP_CONFIDENCE) for ip in _valid_ips(raw_ips)]
    return findings


@register
class HarvesterModule:
    """Subdominios, emails e IPs de un dominio obtenidos con theHarvester.

    No se recogen nombres de personas ni URLs: producen muchos falsos
    positivos y son datos personales.
    """

    name = "harvester"
    accepts = frozenset({"domain"})
    web_opt_in = True
    web_label = "theHarvester"
    web_description = (
        "Herramienta externa opcional para dominios; requiere instalación y fuentes configuradas."
    )

    def __init__(
        self,
        runner: Callable[[Sequence[str]], CliResult] = run_cli,
        sources: str | None = None,
    ) -> None:
        """Ejecutor y fuentes se pueden inyectar. Sin fuentes, se leen de la configuración."""
        self._runner = runner
        self._sources = sources

    def _resolve_sources(self) -> str:
        """Fuentes validadas: las inyectadas o, si no hay, las de la configuración."""
        if self._sources:
            return parse_sources(self._sources)
        return load_settings().harvester_sources

    def run(self, target: Target) -> list[Finding]:
        if not target.domain:
            return []
        sources = self._resolve_sources()

        # Carpeta temporal: theHarvester escribe sus ficheros y no dejamos basura.
        with tempfile.TemporaryDirectory(prefix="osint-harvester-") as tmp:
            base = Path(tmp) / "harvest"
            command = [EXECUTABLE, "-d", target.domain, "-b", sources, "-f", str(base)]
            try:
                result = self._runner(command)
            except ToolNotFoundError as exc:
                raise ModuleSkipped("theHarvester no está instalado") from exc
            data = _read_json(base.with_suffix(".json"))

        if data is None:
            # Sin JSON no se puede afirmar "sin resultados": se informa como fallo.
            raise ExternalToolError(
                f"theHarvester no generó un JSON legible (código {result.returncode})"
            )
        return _to_findings(data, target.domain)
