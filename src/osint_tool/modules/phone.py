"""Módulo de teléfono: país, tipo de línea y operador (análisis local, sin red).

Solo describe el número. No identifica a su titular.
"""

from __future__ import annotations

import logging

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberType, carrier, geocoder

from osint_tool.models import Finding, Target
from osint_tool.registry import register

logger = logging.getLogger(__name__)

SOURCE = "phonenumbers"
LANG = "es"
# El operador asignado al prefijo no es el actual si el número se portó.
CARRIER_CONFIDENCE = 0.5

LINE_TYPES = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.VOIP: "voip",
}


def _finding(type_: str, value: str, confidence: float = 1.0) -> Finding:
    return Finding(
        entity_type="phone",
        type=type_,
        value=value,
        source=SOURCE,
        confidence=confidence,
    )


@register
class PhoneModule:
    """Describe un teléfono en formato internacional (E.164)."""

    name = "phone"
    accepts = frozenset({"phone"})

    def run(self, target: Target) -> list[Finding]:
        if not target.phone:
            return []

        try:
            number = phonenumbers.parse(target.phone, None)
        except NumberParseException:
            logger.info("El teléfono no se pudo interpretar")
            return []
        if not phonenumbers.is_valid_number(number):
            logger.info("El teléfono tiene formato correcto pero no es un número real")
            return []

        findings: list[Finding] = []

        region = phonenumbers.region_code_for_number(number)
        place = geocoder.description_for_number(number, LANG)
        if region:
            findings.append(_finding("phone_region", f"{region} ({place})" if place else region))

        line_type = LINE_TYPES.get(phonenumbers.number_type(number), "other")
        findings.append(_finding("phone_line_type", line_type))

        operator = carrier.name_for_number(number, LANG)
        if operator:  # muchos países no tienen datos de operador
            findings.append(_finding("phone_carrier", operator, CARRIER_CONFIDENCE))
        return findings