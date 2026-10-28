"""Validación de entradas con listas blancas (regex).

Es la barrera de seguridad: ningún dato llega a un comando, una consulta DNS
o una URL sin pasar antes por aquí. Construye un `Target` ya normalizado.
"""

from __future__ import annotations

import re
import unicodedata

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat

from osint_tool.models import Target

MAX_DOMAIN_LENGTH = 253
MAX_EMAIL_LENGTH = 254
MAX_PHONE_INPUT_LENGTH = 64

# Etiquetas de 1-63 caracteres alfanuméricos o guion (no al inicio/final).
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# El TLD puede ser alfabético o punycode (xn--...), para dominios internacionales.
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
_DOMAIN_RE = re.compile(rf"(?:{_LABEL}\.)+{_TLD}")
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}")
MAX_USERNAME_LENGTH = 39  # el máximo de GitHub, el más largo de las plataformas habituales
# Debe empezar por letra, número o "_": así nunca se confunde con una opción (-x) ni con "..".
_USERNAME_RE = re.compile(rf"[A-Za-z0-9_][A-Za-z0-9_.-]{{0,{MAX_USERNAME_LENGTH - 1}}}")
# Letras (incluye acentos y ñ), espacios, apóstrofos, guiones y puntos.
_NAME_RE = re.compile(r"[^\W\d_](?:[^\W\d_]|[ '.\-]){1,99}")


class ValidationError(ValueError):
    """Una entrada no cumple el formato permitido."""


# Tratar espacios exteriores y campos vacíos igual evita entradas vacías en Target.
def _clean(value: str | None) -> str | None:
    """Quita espacios; una cadena vacía equivale a no informado."""
    if value is None:
        return None
    value = value.strip()
    return value or None


# Un único formato de error mantiene comprensibles los rechazos en todas las interfaces.
def _fail(field: str, hint: str) -> ValidationError:
    return ValidationError(f"{field} no válido: {hint}")


# Convertir IDN antes de validar permite comparar y consultar dominios de forma consistente.
def _to_ascii_domain(domain: str) -> str:
    """Convierte dominios internacionales (españa.es) a punycode; ASCII queda igual."""
    if domain.isascii():
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise _fail("dominio", "caracteres internacionales no admitidos") from None


# Canonicalizar aquí evita que cada módulo maneje variantes equivalentes del dominio.
def validate_domain(value: str) -> str:
    """Devuelve el dominio en minúsculas, en ASCII y sin punto final, o lanza error."""
    domain = _to_ascii_domain(value.strip().lower().rstrip("."))
    if len(domain) > MAX_DOMAIN_LENGTH or not _DOMAIN_RE.fullmatch(domain):
        raise _fail("dominio", "usa un formato como ejemplo.com")
    return domain


# Validar el dominio por separado reutiliza las mismas reglas de normalización.
def validate_email(value: str) -> str:
    """Devuelve el email normalizado (dominio en minúsculas), o lanza error."""
    email = value.strip()
    local, sep, domain = email.rpartition("@")
    if not sep or len(email) > MAX_EMAIL_LENGTH or not _EMAIL_LOCAL_RE.fullmatch(local):
        raise _fail("email", "usa un formato como usuario@ejemplo.com")
    try:
        domain = validate_domain(domain)
    except ValidationError:
        raise _fail("email", "el dominio no es válido") from None
    return f"{local}@{domain}"


# Una lista blanca también evita que nombres de usuario se interpreten como opciones externas.
def validate_username(value: str) -> str:
    """Valida un nombre de usuario (1-39 caracteres: letras, números, _ . -)."""
    username = value.strip()
    if not _USERNAME_RE.fullmatch(username):
        raise _fail(
            "username",
            f"1-{MAX_USERNAME_LENGTH} caracteres; empieza por letra, número o _; admite . -",
        )
    return username


# Libphonenumber aporta reglas de numeración internacionales sin inferir un país por longitud.
def validate_phone(value: str, region: str | None = None) -> str:
    """Normaliza a E.164 un número internacional o nacional con región ISO explícita."""
    phone = value.strip()
    region = region.strip().upper() if region else None
    if not phone or len(phone) > MAX_PHONE_INPUT_LENGTH:
        raise _fail("teléfono", "longitud no válida")
    if region and region not in phonenumbers.SUPPORTED_REGIONS:
        raise _fail("región de teléfono", "usa un código ISO 3166-1 alfa-2 válido, p. ej. US")
    if not re.fullmatch(r"\+?[0-9 .()\-]+", phone):
        raise _fail("teléfono", "usa dígitos y separadores comunes, sin extensión")
    try:
        parsed = phonenumbers.parse(phone, region)
    except NumberParseException:
        raise _fail(
            "teléfono",
            "usa E.164 (p. ej. +14155552671) o indica la región ISO del número nacional",
        ) from None
    if not phonenumbers.is_valid_number(parsed):
        raise _fail("teléfono", "el número no es válido para el plan de numeración indicado")
    return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)


# NFC y espacios uniformes reducen resultados distintos por diferencias de escritura.
def validate_name(value: str) -> str:
    """Valida un nombre de persona: normaliza acentos (NFC) y colapsa espacios repetidos."""
    name = " ".join(unicodedata.normalize("NFC", value).split())
    if not _NAME_RE.fullmatch(name):
        raise _fail("nombre", "solo letras, espacios, apóstrofos, guiones y puntos")
    return name


# Construir solo tras validar centraliza la garantía de entrada para todos los consumidores.
def build_target(  # noqa: PLR0913
    *,
    email: str | None = None,
    username: str | None = None,
    domain: str | None = None,
    phone: str | None = None,
    phone_region: str | None = None,
    name: str | None = None,
) -> Target:
    """Valida cada dato informado y construye un `Target` normalizado.

    Raises:
        ValidationError: si algún dato tiene formato inválido o no hay ninguno.
    """
    email, username, domain, phone, phone_region, name = (
        _clean(v) for v in (email, username, domain, phone, phone_region, name)
    )
    if phone_region and not phone:
        raise _fail("región de teléfono", "requiere un teléfono")
    try:
        return Target(
            email=validate_email(email) if email else None,
            username=validate_username(username) if username else None,
            domain=validate_domain(domain) if domain else None,
            phone=validate_phone(phone, phone_region) if phone else None,
            name=validate_name(name) if name else None,
        )
    except ValidationError:
        raise
    except ValueError as exc:  # Target vacío
        raise ValidationError(str(exc)) from exc