import pytest
from phonenumbers import carrier

from osint_tool.models import Target
from osint_tool.modules.phone import PhoneModule


def _by_type(phone: str) -> dict[str, str]:
    findings = PhoneModule().run(Target(phone=phone))
    return {f.type: f.value for f in findings}


def test_movil_espanol() -> None:
    data = _by_type("+34612345678")
    assert data["phone_region"].startswith("ES")
    assert data["phone_line_type"] == "mobile"


def test_otro_pais() -> None:
    assert _by_type("+16502530000")["phone_region"].startswith("US")


def test_numero_no_real_no_produce_hallazgos() -> None:
    assert PhoneModule().run(Target(phone="+3412345")) == []


def test_operador_con_confianza_baja(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(carrier, "name_for_number", lambda number, lang: "Operador X")
    findings = PhoneModule().run(Target(phone="+34612345678"))
    operator = next(f for f in findings if f.type == "phone_carrier")
    assert operator.value == "Operador X"
    assert operator.confidence < 1.0


def test_formato_de_los_hallazgos() -> None:
    findings = PhoneModule().run(Target(phone="+34612345678"))
    assert findings
    assert all(f.source == "phonenumbers" and f.entity_type == "phone" for f in findings)


def test_sin_telefono_devuelve_vacio() -> None:
    assert PhoneModule().run(Target(domain="ejemplo.com")) == []