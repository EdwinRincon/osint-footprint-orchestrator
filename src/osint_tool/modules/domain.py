"""Módulo de dominio: registros DNS y datos públicos de WHOIS."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

import dns.exception
import dns.resolver
import whois
from whois.exceptions import WhoisError

from osint_tool.config import load_settings
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import register
from osint_tool.validation import ValidationError, validate_email

logger = logging.getLogger(__name__)

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


# Mantener el timeout central evita consultas WHOIS indefinidamente bloqueadas.
def _default_whois(domain: str) -> Mapping[str, Any]:
    """Consulta WHOIS real con el timeout de la configuración."""
    result: Mapping[str, Any] = whois.whois(domain, timeout=int(load_settings().http_timeout))
    return result


# WHOIS varía el tipo de algunos campos; una forma única simplifica el tratamiento posterior.
def _as_list(value: Any) -> list[Any]:
    """WHOIS devuelve a veces un valor y a veces una lista; unifica."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


# Escoger el primer dato utilizable evita duplicados de valores en formatos alternativos.
def _first_text(value: Any) -> str | None:
    """Primer valor no vacío como texto; las fechas salen como YYYY-MM-DD."""
    for item in _as_list(value):
        if isinstance(item, datetime):
            return item.date().isoformat()
        text = str(item).strip()
        if text:
            return text
    return None


# Compartir metadatos evita que los hallazgos WHOIS tengan un contrato distinto.
def _whois_finding(
    entity_type: str, type_: str, value: str, confidence: float = 1.0
) -> Finding:
    return Finding(
        entity_type=entity_type,
        type=type_,
        value=value,
        source="WHOIS",
        confidence=confidence,
    )


@register
class DomainModule:
    """Registros DNS (A, AAAA, MX, NS, TXT) y datos WHOIS de un dominio."""

    name = "domain"
    accepts = frozenset({"domain"})
    web_label = "DNS y WHOIS"
    web_description = "Consulta registros DNS (A, AAAA, MX, NS, TXT) y datos públicos WHOIS."

    # Permitir dependencias inyectadas hace posible probar fallos y respuestas sin red.
    def __init__(
        self,
        resolver: Any = None,
        whois_lookup: Callable[[str], Mapping[str, Any]] | None = None,
    ) -> None:
        """Las dependencias se pueden inyectar para probar sin red."""
        if resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = load_settings().http_timeout
        self._resolver = resolver
        self._whois = whois_lookup or _default_whois

    # Devolver ambas coberturas permite distinguir consultas vacías de fuentes sin respuesta.
    def run(self, target: Target) -> ModuleOutput:
        if not target.domain:
            return ModuleOutput()
        dns_findings, dns_checks = self._dns_findings(target.domain)
        whois_findings, whois_check = self._whois_findings(target.domain)
        return ModuleOutput(
            findings=dns_findings + whois_findings,
            source_checks=[*dns_checks, whois_check],
        )

    # Consultar tipos por separado conserva la cobertura exacta cuando un registro falla.
    def _dns_findings(self, domain: str) -> tuple[list[Finding], list[SourceCheck]]:
        findings: list[Finding] = []
        checks: list[SourceCheck] = []
        for rtype in RECORD_TYPES:
            try:
                answers = self._resolver.resolve(domain, rtype)
            except dns.resolver.NoAnswer:
                checks.append(
                    SourceCheck(f"DNS {rtype}", SourceCheckStatus.NOT_FOUND, "Sin registros.")
                )
                continue
            except dns.resolver.NXDOMAIN:
                logger.info("El dominio %s no existe en DNS", domain)
                # NXDOMAIN se aplica a todos los tipos restantes; no repetir consultas sin sentido.
                checks.extend(
                    SourceCheck(f"DNS {record_type}", SourceCheckStatus.NOT_FOUND, "NXDOMAIN.")
                    for record_type in RECORD_TYPES[len(checks) :]
                )
                break
            except dns.exception.DNSException as exc:
                logger.warning("DNS %s fallo (%s): %s", rtype, domain, type(exc).__name__)
                checks.append(
                    SourceCheck(f"DNS {rtype}", SourceCheckStatus.ERROR, type(exc).__name__)
                )
                continue
            records = [
                Finding(
                    entity_type="domain",
                    type="dns_record",
                    value=f"{rtype} {rdata.to_text()}",
                    source="DNS",
                    raw={"record_type": rtype},
                )
                for rdata in answers
            ]
            findings.extend(records)
            checks.append(
                SourceCheck(
                    f"DNS {rtype}",
                    SourceCheckStatus.FOUND if records else SourceCheckStatus.NOT_FOUND,
                    f"{len(records)} registro(s)." if records else "Sin registros.",
                )
            )
        return findings, checks

    # Tratar WHOIS por separado impide que sus problemas oculten resultados DNS válidos.
    def _whois_findings(
        self, domain: str
    ) -> tuple[list[Finding], SourceCheck]:
        try:
            data = self._whois(domain)
        except (WhoisError, OSError) as exc:
            logger.warning("WHOIS fallo (%s): %s", domain, type(exc).__name__)
            return [], SourceCheck("WHOIS", SourceCheckStatus.ERROR, type(exc).__name__)

        fields = {
            "whois_registrar": "registrar",
            "whois_org": "org",
            "whois_country": "country",
            "whois_created": "creation_date",
            "whois_expires": "expiration_date",
        }
        findings = []
        for type_, key in fields.items():
            text = _first_text(data.get(key))
            if text:
                findings.append(_whois_finding("domain", type_, text))

        # Los emails de WHOIS suelen ser proxies de privacidad: confianza baja.
        for raw_email in dict.fromkeys(str(e) for e in _as_list(data.get("emails"))):
            try:
                email = validate_email(raw_email)
            except ValidationError:
                continue  # texto como "Select Request Email Form"
            findings.append(_whois_finding("email", "whois_contact", email, 0.6))
        status = SourceCheckStatus.FOUND if findings else SourceCheckStatus.NOT_FOUND
        detail = f"{len(findings)} dato(s)." if findings else "Sin datos públicos."
        return findings, SourceCheck("WHOIS", status, detail)