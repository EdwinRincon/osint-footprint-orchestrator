from osint_tool.correlator import correlate
from osint_tool.models import Finding, Target


def _f(type_: str, value: str, source: str, confidence: float = 1.0) -> Finding:
    return Finding(entity_type="x", type=type_, value=value, source=source, confidence=confidence)


def _pairs(relations):  # type: ignore[no-untyped-def]
    return {(r.source, r.target) for r in relations}


def test_datos_de_entrada_no_se_presentan_como_evidencia_de_identidad() -> None:
    target = Target(name="Ana Pérez", username="ana", domain="ejemplo.com")
    assert correlate(target, []) == []


def test_el_nombre_nunca_se_enlaza_con_otros_datos_aportados() -> None:
    target = Target(
        name="Ana Pérez", email="ana@ejemplo.com", username="ana", phone="+34600000000"
    )
    assert correlate(target, []) == []


def test_mismo_username_en_varias_redes() -> None:
    findings = [
        _f("profile", "https://github.com/ana", "GitHub", 0.5),
        _f("profile", "https://reddit.com/user/ana", "Reddit", 0.5),
    ]
    relations = correlate(Target(username="ana"), findings)
    assert _pairs(relations) == {
        ("username:ana", "profile:https://github.com/ana"),
        ("username:ana", "profile:https://reddit.com/user/ana"),
    }
    assert {r.label for r in relations} == {
        "perfil observado en GitHub",
        "perfil observado en Reddit",
    }
    assert {r.evidence for r in relations} == {("GitHub",), ("Reddit",)}
    assert all(r.confidence == 0.5 for r in relations)


def test_dominio_del_email_coincide() -> None:
    relations = correlate(Target(email="ana@ejemplo.com", domain="ejemplo.com"), [])
    assert len(relations) == 1
    assert relations[0].label == "el email termina en el dominio indicado"
    assert relations[0].confidence == 1.0


def test_dominio_del_email_distinto_no_se_enlaza() -> None:
    assert correlate(Target(email="ana@otro.com", domain="ejemplo.com"), []) == []


def test_email_en_un_subdominio_no_se_enlaza_con_el_dominio_principal() -> None:
    assert correlate(Target(email="ana@mail.ejemplo.com", domain="ejemplo.com"), []) == []


def test_varias_fuentes_no_asumen_independencia_estadistica() -> None:
    findings = [
        _f("whois_contact", "info@ejemplo.com", "WHOIS", 0.6),
        _f("harvested_email", "info@ejemplo.com", "theHarvester", 0.7),
    ]
    relations = correlate(Target(domain="ejemplo.com"), findings)
    assert len(relations) == 1
    assert relations[0].label == "contacto WHOIS / email encontrado"
    assert relations[0].confidence == 0.7


def test_la_misma_fuente_repetida_no_suma() -> None:
    findings = [
        _f("whois_contact", "info@ejemplo.com", "WHOIS", 0.6),
        _f("whois_contact", "info@ejemplo.com", "WHOIS", 0.6),
    ]
    assert correlate(Target(domain="ejemplo.com"), findings)[0].confidence == 0.6


def test_brecha_enlazada_al_email() -> None:
    relations = correlate(Target(email="ana@ejemplo.com"), [_f("breach", "Adobe", "XposedOrNot")])
    assert _pairs(relations) == {("email:ana@ejemplo.com", "breach:Adobe")}
    assert relations[0].label == "aparece en brecha"


def test_telefono_enlaza_region_tipo_de_linea_y_operador() -> None:
    findings = [
        _f("phone_region", "ES (España)", "phonenumbers"),
        _f("phone_line_type", "mobile", "phonenumbers"),
        _f("phone_carrier", "DigiMobil", "phonenumbers", 0.5),
    ]
    relations = correlate(Target(phone="+34600000000"), findings)
    assert {(r.target, r.label) for r in relations} == {
        ("region:ES (España)", "región"),
        ("line_type:mobile", "tipo de línea"),
        ("carrier:DigiMobil", "operador"),
    }


def test_las_relaciones_salen_en_orden_determinista() -> None:
    findings = [_f("breach", "Zeta", "XposedOrNot"), _f("breach", "Adobe", "XposedOrNot")]
    relations = correlate(Target(email="ana@ejemplo.com"), findings)
    assert [r.target for r in relations] == ["breach:Adobe", "breach:Zeta"]


def test_tipo_desconocido_se_ignora() -> None:
    assert correlate(Target(domain="ejemplo.com"), [_f("zzz", "algo", "X")]) == []


def test_hallazgo_sin_entidad_de_origen_se_ignora() -> None:
    assert correlate(Target(domain="ejemplo.com"), [_f("breach", "Adobe", "XposedOrNot")]) == []