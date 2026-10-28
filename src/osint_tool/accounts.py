"""Carga del índice de plataformas usado para reconocer cuentas a partir de una URL.

El índice se construye con las plantillas de WhatsMyName (ver `pivots.build_account_index`).
Los alias manuales de `pivots.BUILTIN_ACCOUNT_HOSTS` tienen prioridad sobre el dataset:
si un sitio cambia de URL, el alias integrado sigue ganando.
"""

from __future__ import annotations

from osint_tool.config import Settings, load_settings
from osint_tool.pivots import AccountIndex, build_account_index


# Sin dataset el índice se reduce a los alias integrados, así que la correlación no falla.
def load_account_index(settings: Settings | None = None) -> AccountIndex | None:
    """Índice del dataset configurado; None si no existe o no se puede leer."""
    # Import local: `modules` carga todos los módulos, y `github_profile` importa este fichero.
    from osint_tool.modules.usernames import load_wmn_sites  # noqa: PLC0415

    path = (settings or load_settings()).wmn_file
    try:
        sites = load_wmn_sites(path)
    except (OSError, ValueError):
        return None
    return build_account_index((site.name, site.pretty_url or site.url) for site in sites)
