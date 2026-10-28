"""Caracterización: si el índice WMN falla, `load_account_index` avisa en local y devuelve None.

Invertido a propósito: antes el fallback era silencioso. El aviso no incluye la ruta ni el
mensaje de la excepción, y el valor devuelto (y por tanto report.json/HTML) no cambia.
"""

import logging
from pathlib import Path

import pytest

from osint_tool.accounts import load_account_index
from osint_tool.config import Settings, load_settings


def _settings(wmn_file: Path) -> Settings:
    return Settings(**{**load_settings().__dict__, "wmn_file": wmn_file})


def test_indice_ausente_devuelve_none_y_avisa_sin_la_ruta(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ruta = tmp_path / "datos-personales-ana.json"
    with caplog.at_level(logging.DEBUG):
        assert load_account_index(_settings(ruta)) is None
    avisos = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(avisos) == 1
    assert "FileNotFoundError" in avisos[0].getMessage()
    assert "datos-personales-ana" not in caplog.text
    assert str(tmp_path) not in caplog.text


@pytest.mark.parametrize("contenido", ["{no es json", '{"sin_sites": []}', '{"sites": 3}'])
def test_indice_corrupto_devuelve_none_y_avisa_sin_el_nombre_del_fichero(
    contenido: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fichero = tmp_path / "datos-personales-ana.json"
    fichero.write_text(contenido, encoding="utf-8")
    with caplog.at_level(logging.DEBUG):
        assert load_account_index(_settings(fichero)) is None
    avisos = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(avisos) == 1
    assert "ValueError" in avisos[0].getMessage()
    assert "datos-personales-ana" not in caplog.text
    assert contenido not in caplog.text


def test_indice_valido_no_es_none_y_no_avisa(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fichero = tmp_path / "wmn.json"
    fichero.write_text(
        '{"sites": [{"name": "Foo", "uri_check": "https://foo.com/{account}"}]}',
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        assert load_account_index(_settings(fichero)) is not None
    assert caplog.records == []
