"""Caracterización: un teléfono inválido no debe aparecer en los logs.

Invertido a propósito: antes el número completo se escribía en INFO.
"""

import logging

import pytest

from osint_tool.models import Target
from osint_tool.modules.phone import PhoneModule


@pytest.mark.parametrize("numero", ["+1234", "+34000000000"])
def test_telefono_invalido_no_da_hallazgos_ni_se_registra(
    numero: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        assert PhoneModule().run(Target(phone=numero)) == []
    assert numero not in caplog.text
    assert numero.lstrip("+") not in caplog.text
    assert "Número de teléfono ignorado" in caplog.text


def test_sin_telefono_no_registra_nada(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        assert PhoneModule().run(Target(username="ana")) == []
    assert caplog.text == ""
