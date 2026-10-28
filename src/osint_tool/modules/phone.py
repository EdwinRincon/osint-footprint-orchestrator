"""Módulo de teléfono: país, tipo de línea y operador (análisis local, sin red).

Solo describe el número. No identifica a su titular.
"""

from __future__ import annotations

import logging

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumber, PhoneNumberType, carrier, geocoder

from osint_tool.models import Finding, Target
from osint_tool.registry import ModuleSkipped, register

logger = logging.getLogger(__name__)

SOURCE = "phonenumbers"
LANG = "es"
# El operador asignado al prefijo no es el actual si el número se portó.
CARRIER_CONFIDENCE = 0.5

LINE_TYPES: dict[int, str] = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}
LINE_TYPE_FALLBACK = "other"


# Compartir origen y estructura evita diferencias entre los metadatos derivados del número.
def _finding(type_: str, value: str, confidence: float = 1.0) -> Finding:
    # Compartir la etiqueta de fuente facilita atribuir metadatos calculados localmente.
    return Finding(
        entity_type="phone",
        type=type_,
        value=value,
        source=SOURCE,
        confidence=confidence,
    )


# Omitir números no válidos evita presentar metadatos de prefijo como datos de una línea real.
def _parse_valid(raw: str) -> PhoneNumber:
    """Interpreta el número (formato internacional) o lanza `ModuleSkipped`."""
    try:
        number = phonenumbers.parse(raw, None)
    except NumberParseException as exc:
        logger.info("El teléfono no se pudo interpretar")
        raise ModuleSkipped("El teléfono no se pudo interpretar.") from exc
    if not phonenumbers.is_valid_number(number):
        logger.info("El teléfono tiene formato correcto pero no es un número real")
        raise ModuleSkipped("El teléfono tiene formato correcto pero no es un número real.")
    return number


# Una región ausente debe seguir ausente en vez de convertirse en una ubicación inventada.
def _region_finding(number: PhoneNumber) -> Finding | None:
    # No inventar una región mantiene explícita la falta de datos del prefijo.
    region = phonenumbers.region_code_for_number(number)
    if not region:
        return None
    place = geocoder.description_for_number(number, LANG)
    return _finding("phone_region", f"{region} ({place})" if place else region)


# Conservar tipos desconocidos ayuda a distinguir falta de metadatos de error de consulta.
def _line_type_finding(number: PhoneNumber) -> Finding:
    # El valor de reserva conserva el hallazgo cuando la biblioteca desconoce el tipo.
    line_type = LINE_TYPES.get(phonenumbers.number_type(number), LINE_TYPE_FALLBACK)
    return _finding("phone_line_type", line_type)


# Dejar vacío el operador desconocido evita atribuir una compañía sin respaldo.
def _carrier_finding(number: PhoneNumber) -> Finding | None:
    operator = carrier.name_for_number(number, LANG)
    # Muchos países no tienen datos de operador.
    return _finding("phone_carrier", operator, CARRIER_CONFIDENCE) if operator else None


@register
class PhoneModule:
    """Describe un teléfono en formato internacional (E.164)."""

    name = "phone"
    accepts = frozenset({"phone"})
    web_label = "Metadatos del teléfono"
    web_description = (
        "Deriva región, tipo de línea y prefijo de operador; no identifica a su titular."
    )

    # Mantener el análisis local evita enviar el número a servicios externos.
    def run(self, target: Target) -> list[Finding]:
        if not target.phone:
            return []

        try:
            number = _parse_valid(target.phone)
        except ModuleSkipped:
            logger.info("Número de teléfono ignorado")
            return []

        candidates = (
            _region_finding(number),
            _line_type_finding(number),
            _carrier_finding(number),
        )
        return [finding for finding in candidates if finding is not None]