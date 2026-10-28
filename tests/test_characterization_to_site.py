"""Caracterización de las URLs que `_to_site` admite (el dataset WMN no es confiable).

Política: solo `https` con host público. Invertidos a propósito respecto a la línea base
anterior: los casos http, IP privada/loopback/link-local, localhost y esquemas distintos
de https, que antes se admitían y ahora se descartan.
"""

import json
import logging
from typing import Any

import pytest

from osint_tool.modules.usernames import _to_site, load_wmn_sites


def _entry(uri_check: Any, **extra: Any) -> dict[str, Any]:
    return {"name": "Sitio", "uri_check": uri_check, **extra}


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.com/{account}",
        "https://{account}.example.com/",
        "https://example.com:8443/{account}",
        "https://8.8.8.8/{account}",
    ],
)
def test_se_admite_https_con_host_publico(uri: str) -> None:
    site = _to_site(_entry(uri))
    assert site is not None
    assert site.url == uri.replace("{account}", "{username}")


@pytest.mark.parametrize(
    "uri",
    [
        "http://example.com/{account}",
        "http://192.168.1.10/{account}",
        "https://127.0.0.1/{account}",
        "https://10.0.0.5/{account}",
        "https://localhost/{account}",
        "https://app.localhost/{account}",
        "http://localhost:8080/{account}",
        "https://[::1]/{account}",
        "https://[::ffff:127.0.0.1]/{account}",
        "https://169.254.169.254/latest/{account}",
        "https://2130706433/{account}",
        "https://intranet/{account}",
        "ftp://example.com/{account}",
        "//example.com/{account}",
    ],
)
def test_se_descarta_lo_que_no_es_https_con_host_publico(uri: str) -> None:
    assert _to_site(_entry(uri)) is None


@pytest.mark.parametrize(
    "entry",
    [
        {"uri_check": "https://example.com/{account}"},
        {"name": 3, "uri_check": "https://example.com/{account}"},
        {"name": "Sitio"},
        {"name": "Sitio", "uri_check": None},
        {"name": "Sitio", "uri_check": 5},
        {"name": "Sitio", "uri_check": "https://example.com/sin-marcador"},
    ],
)
def test_entradas_sin_nombre_o_plantilla_valida_se_rechazan(entry: dict[str, Any]) -> None:
    assert _to_site(entry) is None


def test_uri_pretty_solo_se_conserva_si_es_texto() -> None:
    con_texto = _to_site(_entry("https://a.com/{account}", uri_pretty="http://b.com/{account}"))
    assert con_texto is not None
    assert con_texto.pretty_url == "http://b.com/{username}"
    sin_texto = _to_site(_entry("https://a.com/{account}", uri_pretty=7))
    assert sin_texto is not None
    assert sin_texto.pretty_url is None


def test_load_wmn_sites_descarta_plantillas_no_seguras_y_registra_solo_el_numero(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    fichero = tmp_path / "wmn.json"
    fichero.write_text(
        json.dumps(
            {
                "sites": [
                    _entry("https://ok.example/{account}"),
                    {**_entry("http://10.0.0.5/{account}"), "name": "Privado"},
                    {**_entry("http://localhost/{account}"), "name": "Local"},
                    {**_entry("https://x.example/{account}"), "protection": ["cf"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level(logging.INFO):
        nombres = [site.name for site in load_wmn_sites(fichero)]
    assert nombres == ["Sitio"]
    assert "Plantillas descartadas por no ser https con host público: 2" in caplog.text
    assert "10.0.0.5" not in caplog.text
    assert "localhost" not in caplog.text


def test_si_no_se_descarta_nada_no_se_registra_el_descarte(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    fichero = tmp_path / "wmn.json"
    fichero.write_text(json.dumps({"sites": [_entry("https://ok.example/{account}")]}), "utf-8")
    with caplog.at_level(logging.INFO):
        assert len(load_wmn_sites(fichero)) == 1
    assert "descartadas" not in caplog.text
