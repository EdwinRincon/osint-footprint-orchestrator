"""Pivotes: identificadores que un perfil declara y que permiten enlazarlo con otras entidades.

Todo aquí es puro (sin red, sin reloj). Un pivote es una pista para correlacionar,
no una prueba de identidad: solo indica que el perfil declara ese identificador.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from osint_tool.validation import ValidationError, validate_domain, validate_email

# Tipos de pivote que se convierten en nodos del grafo.
KIND_ACCOUNT = "account"
KIND_WEBSITE = "website"
KIND_EMAIL = "email"
KIND_GRAVATAR = "gravatar"
PIVOT_KINDS: frozenset[str] = frozenset({KIND_ACCOUNT, KIND_WEBSITE, KIND_EMAIL, KIND_GRAVATAR})

# host -> {prefijo de ruta -> plataforma}. El prefijo son los segmentos anteriores a la cuenta:
# reddit.com/user/{cuenta} se guarda como {"reddit.com": {("user",): "reddit"}}.
AccountIndex = dict[str, dict[tuple[str, ...], str]]

# El dataset no sabe que x.com y twitter.com son la misma plataforma ni incluye GitHub
# (lo excluye por su protección anti-automatización), así que estos alias se mantienen a mano.
BUILTIN_ACCOUNT_HOSTS: AccountIndex = {
    "twitter.com": {(): "twitter"},
    "mobile.twitter.com": {(): "twitter"},
    "x.com": {(): "twitter"},
    "github.com": {(): "github"},
    "gitlab.com": {(): "gitlab"},
    "instagram.com": {(): "instagram"},
}

_ACCOUNT_SLOT = "\0"  # marca temporal de dónde va la cuenta en una plantilla
USERNAME_PLACEHOLDER = "{username}"

# Primeros segmentos de ruta que no son nombres de cuenta.
_RESERVED_SEGMENTS = frozenset(
    {"about", "explore", "home", "i", "intent", "login", "orgs", "search", "settings", "share"}
)
_HANDLE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,38}")
_GRAVATAR_RE = re.compile(r"[0-9a-f]{32}")
_WEB_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True)
class Pivot:
    """Identificador declarado por un perfil.

    Attributes:
        kind: tipo de pivote (uno de `PIVOT_KINDS`), que es también el tipo de nodo.
        value: valor ya normalizado.
        explicit: True si el propio perfil lo declara como enlace o dato de contacto;
            False si es solo una coincidencia de identificador más débil.
    """

    kind: str
    value: str
    explicit: bool

    def to_dict(self) -> dict[str, Any]:
        """Forma serializable para `Finding.raw`."""
        return {"kind": self.kind, "value": self.value, "explicit": self.explicit}

    # Tolerar datos mal formados evita que un `raw` corrupto rompa la correlación.
    @staticmethod
    def from_dict(data: Any) -> Pivot | None:
        """Reconstruye un pivote; None si falta algún campo o el tipo no es válido."""
        if not isinstance(data, dict):
            return None
        kind, value, explicit = data.get("kind"), data.get("value"), data.get("explicit")
        if kind not in PIVOT_KINDS or not isinstance(value, str) or not value:
            return None
        if not isinstance(explicit, bool):
            return None
        return Pivot(kind=kind, value=value, explicit=explicit)


def _handle(value: str) -> str | None:
    handle = value.strip().lstrip("@")
    if handle.lower() in _RESERVED_SEGMENTS or not _HANDLE_RE.fullmatch(handle):
        return None
    return handle.lower()


def _platform_key(name: str) -> str:
    """Nombre de plataforma estable: 'Reddit (User)' -> 'reddit'."""
    base = re.sub(r"\s*\(.*?\)", "", name).lower()
    return re.sub(r"[^a-z0-9]+", "-", base).strip("-")


def _template_entry(name: str, template: str) -> tuple[str, tuple[str, ...], str] | None:
    """(host, prefijo, plataforma) si la cuenta es el último segmento de la ruta; si no, None."""
    try:
        parsed = urlparse(template.replace(USERNAME_PLACEHOLDER, _ACCOUNT_SLOT))
    except ValueError:
        return None
    host = (parsed.hostname or "").removeprefix("www.")
    segments = [s for s in parsed.path.split("/") if s]
    elsewhere = (parsed.netloc, parsed.query, parsed.fragment, *segments[:-1])
    platform = _platform_key(name)
    if (
        parsed.scheme not in _WEB_SCHEMES
        or not host
        or not platform
        or not segments
        or segments[-1] != _ACCOUNT_SLOT
        or any(_ACCOUNT_SLOT in part for part in elsewhere)
    ):
        return None
    return host, tuple(s.lower() for s in segments[:-1]), platform


# Reutilizar las plantillas de WhatsMyName evita mantener a mano una lista de plataformas.
def build_account_index(
    sites: Iterable[tuple[str, str]], aliases: AccountIndex | None = None
) -> AccountIndex:
    """Índice host -> plantillas a partir de pares (nombre, URL con {username}).

    Solo sirven las plantillas donde la cuenta es el último segmento de la ruta; el resto
    se ignora. Si un host y un prefijo se repiten, gana la primera. Los `aliases`
    (por defecto, `BUILTIN_ACCOUNT_HOSTS`) tienen prioridad sobre el dataset.
    """
    index: AccountIndex = {}
    for name, template in sites:
        entry = _template_entry(name, template)
        if entry is not None:
            host, prefix, platform = entry
            index.setdefault(host, {}).setdefault(prefix, platform)
    for host, prefixes in (BUILTIN_ACCOUNT_HOSTS if aliases is None else aliases).items():
        index.setdefault(host, {}).update(prefixes)
    return index


def _account_from_url(value: str, index: AccountIndex) -> str | None:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").removeprefix("www.")
    if parsed.scheme not in _WEB_SCHEMES or parsed.username:
        return None
    segments = [s for s in parsed.path.split("/") if s]
    # El prefijo más largo gana: reddit.com/user/{cuenta} antes que reddit.com/{cuenta}.
    for prefix, platform in sorted(index.get(host, {}).items(), key=lambda item: -len(item[0])):
        size = len(prefix)
        if len(segments) > size and tuple(s.lower() for s in segments[:size]) == prefix:
            handle = _handle(segments[size])
            return f"{platform}:{handle}" if handle else None
    return None


# Una sola clave por cuenta permite que perfiles con URL distintas se fusionen en el grafo.
def canonical_account(
    value: str, platform: str | None = None, index: AccountIndex | None = None
) -> str | None:
    """Clave canónica 'plataforma:cuenta' o None si no se reconoce.

    Acepta una URL de una plataforma del índice (`https://x.com/Ana`) o un nombre de
    cuenta (`@Ana`) acompañado de su `platform`. Solo admite http y https. Sin `index`
    se usan únicamente los alias integrados.
    """
    index = BUILTIN_ACCOUNT_HOSTS if index is None else index
    value = value.strip()
    if "/" in value or "://" in value:
        return _account_from_url(value, index)
    known = {name for prefixes in index.values() for name in prefixes.values()}
    if platform is None or platform not in known:
        return None
    handle = _handle(value)
    return f"{platform}:{handle}" if handle else None


# Descartar esquemas ajenos (javascript:, data:) evita convertir enlaces activos en datos.
def normalize_website(value: str) -> str | None:
    """URL web normalizada (https por omisión, sin 'www.', sin barra final) o None."""
    value = value.strip()
    if not value or any(char.isspace() for char in value):
        return None
    parsed = urlparse(value if "://" in value else f"https://{value}")
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in _WEB_SCHEMES or parsed.username or not parsed.hostname:
        return None
    try:
        host = validate_domain(parsed.hostname.removeprefix("www."))
    except ValidationError:
        return None
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{netloc}{path}"


def _website_or_account(value: str, index: AccountIndex | None) -> Pivot | None:
    account = canonical_account(value, index=index)
    if account is not None:
        return Pivot(KIND_ACCOUNT, account, explicit=True)
    website = normalize_website(value)
    return Pivot(KIND_WEBSITE, website, explicit=True) if website else None


def _email_pivot(value: str) -> Pivot | None:
    try:
        return Pivot(KIND_EMAIL, validate_email(value).lower(), explicit=True)
    except ValidationError:
        return None


def _text(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


# La ubicación y la empresa no son pivotes: conectarían a miles de personas distintas.
def extract_github(payload: dict[str, Any], index: AccountIndex | None = None) -> list[Pivot]:
    """Pivotes de la respuesta de `GET /users/{login}` de GitHub."""
    pivots: list[Pivot] = []
    blog = _text(payload, "blog")
    if blog and (pivot := _website_or_account(blog, index)):
        pivots.append(pivot)
    twitter = _text(payload, "twitter_username")
    if twitter and (account := canonical_account(twitter, "twitter", index)):
        pivots.append(Pivot(KIND_ACCOUNT, account, explicit=True))
    email = _text(payload, "email")
    if email and (email_pivot := _email_pivot(email)):
        pivots.append(email_pivot)
    gravatar = (_text(payload, "gravatar_id") or "").lower()
    if _GRAVATAR_RE.fullmatch(gravatar):
        pivots.append(Pivot(KIND_GRAVATAR, gravatar, explicit=False))
    return list(dict.fromkeys(pivots))
