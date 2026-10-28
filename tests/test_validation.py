import pytest

from osint_tool.validation import (
    ValidationError,
    build_target,
    validate_domain,
    validate_email,
    validate_name,
    validate_phone,
    validate_username,
)


def test_normaliza_datos_validos() -> None:
    t = build_target(
        email=" Test@Example.COM ",
        domain="Ejemplo.com.",
        phone="+34 600-000-000",
        name="  Ana   Pérez ",
        username="ana_perez",
    )
    assert t.email == "Test@example.com"
    assert t.domain == "ejemplo.com"
    assert t.phone == "+34600000000"
    assert t.name == "Ana Pérez"
    assert t.username == "ana_perez"


def test_sin_datos_falla() -> None:
    with pytest.raises(ValidationError):
        build_target()
    with pytest.raises(ValidationError):
        build_target(email="   ")


@pytest.mark.parametrize(
    "campo, valor",
    [
        ("email", "sin-arroba"),
        ("email", "a@b"),
        ("domain", "ejemplo.com; rm -rf /"),
        ("domain", "-malo.com"),
        ("domain", "a..com"),
        ("username", "con espacios"),
        ("username", "x" * 40),
        ("username", "-rf"),
        ("username", ".."),
        ("username", ".oculto"),
        ("phone", "642775948"),
        ("phone", "+0123456"),
        ("name", "Ana123"),
        ("name", "<script>"),
    ],
)
def test_entradas_invalidas(campo: str, valor: str) -> None:
    with pytest.raises(ValidationError):
        build_target(**{campo: valor})


def test_normaliza_todos_los_campos_con_build_target() -> None:
    target = build_target(email="Ana@Ejemplo.com", domain="Ejemplo.com", name=" Ana   Pérez ")
    assert target.to_dict() == {
        "email": "Ana@ejemplo.com",
        "domain": "ejemplo.com",
        "name": "Ana Pérez",
    }


def test_dominio_internacional_se_convierte_a_punycode() -> None:
    assert validate_domain("España.es") == "xn--espaa-rta.es"


def test_dominio_con_tld_punycode_es_valido() -> None:
    assert validate_domain("ejemplo.xn--p1ai") == "ejemplo.xn--p1ai"


@pytest.mark.parametrize("value", ["ejemplo", "ejemplo..com", "a b.com", "x.c"])
def test_dominio_invalido_se_rechaza(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_domain(value)


def test_email_valida_su_dominio() -> None:
    assert validate_email(" Ana@EJEMPLO.com ") == "Ana@ejemplo.com"
    with pytest.raises(ValidationError):
        validate_email("ana@sin-tld")


def test_el_error_no_repite_el_valor_recibido() -> None:
    with pytest.raises(ValidationError) as caught:
        validate_email("secreto@@x")
    assert "secreto" not in str(caught.value)


def test_nombre_con_acentos_descompuestos_se_normaliza() -> None:
    assert validate_name("José  Pérez") == validate_name("Jose\u0301  Pe\u0301rez")


@pytest.mark.parametrize("value", ["ana", "_ana", "ana.perez-99", "7ana", "a" * 39])
def test_username_valido_se_acepta(value: str) -> None:
    assert validate_username(value) == value


def test_username_de_mas_de_39_caracteres_se_rechaza() -> None:
    with pytest.raises(ValidationError):
        validate_username("a" * 40)


def test_telefono_se_normaliza_a_e164() -> None:
    assert validate_phone("+34 600 000-000") == "+34600000000"


def test_telefono_nacional_espanol_se_normaliza_a_e164() -> None:
    assert validate_phone("642775948", "ES") == "+34642775948"


@pytest.mark.parametrize(
    ("value", "region", "expected"),
    [
        ("202 555 0123", "US", "+12025550123"),
        ("020 7946 0018", "GB", "+442079460018"),
        ("300 123 4567", "CO", "+573001234567"),
        ("90 1234 5678", "JP", "+819012345678"),
    ],
)
def test_telefonos_nacionales_se_normalizan_segun_su_region(
    value: str, region: str, expected: str
) -> None:
    assert validate_phone(value, region) == expected


@pytest.mark.parametrize(
    "value",
    ["+34642775948", "+14155552671", "+442079460018", "+573001234567"],
)
def test_telefonos_internacionales_validos_de_distintos_paises(value: str) -> None:
    assert validate_phone(value) == value


def test_numero_nacional_sin_region_se_rechaza() -> None:
    with pytest.raises(ValidationError):
        validate_phone("642775948")


def test_region_de_telefono_invalida_se_rechaza() -> None:
    with pytest.raises(ValidationError):
        validate_phone("2025550123", "ZZ")


def test_region_no_se_acepta_sin_numero() -> None:
    with pytest.raises(ValidationError):
        build_target(phone_region="US")


def test_build_target_usa_region_solo_para_normalizar_el_telefono() -> None:
    target = build_target(phone="2025550123", phone_region="US")
    assert target.phone == "+12025550123"
    assert target.to_dict() == {"phone": "+12025550123"}