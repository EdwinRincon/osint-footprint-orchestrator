from pathlib import Path

import pytest

from osint_tool.correlator import correlate
from osint_tool.models import Finding, Target
from osint_tool.modules.usernames import _build_finding, load_wmn_sites

WMN_PATH = Path(__file__).resolve().parents[1] / "data" / "wmn-data.json"


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


def _gh(login: str, *pivots: dict[str, object]) -> Finding:
    return Finding(
        entity_type="public_profile",
        type="github_profile",
        value=f"https://github.com/{login}",
        source="GitHub",
        confidence=0.5,
        raw={"pivots": list(pivots)},
    )


def _pivot(kind: str, value: str, explicit: bool = True) -> dict[str, object]:
    return {"kind": kind, "value": value, "explicit": explicit}


def test_pivote_explicito_crea_la_arista_del_perfil() -> None:
    finding = _gh("ana", _pivot("website", "https://ana.dev"))
    relations = correlate(Target(username="ana"), [finding])
    assert _pairs(relations) == {
        ("username:ana", "profile:https://github.com/ana"),
        ("profile:https://github.com/ana", "website:https://ana.dev"),
    }
    pivot_relation = next(r for r in relations if r.target.startswith("website:"))
    assert (pivot_relation.confidence, pivot_relation.evidence) == (0.6, ("GitHub",))


def test_pivote_debil_tiene_menos_confianza() -> None:
    finding = _gh("ana", _pivot("gravatar", "a" * 32, explicit=False))
    relations = correlate(Target(username="ana"), [finding])
    assert next(r for r in relations if r.target.startswith("gravatar:")).confidence == 0.3


def test_dos_perfiles_con_el_mismo_pivote_comparten_nodo() -> None:
    findings = [
        _gh("ana", _pivot("email", "ana@ejemplo.com")),
        _gh("ana-dev", _pivot("email", "ana@ejemplo.com")),
    ]
    relations = correlate(Target(username="ana"), findings)
    assert {r.source for r in relations if r.target == "email:ana@ejemplo.com"} == {
        "profile:https://github.com/ana",
        "profile:https://github.com/ana-dev",
    }


def test_el_email_publico_se_une_al_email_hallado_por_otra_fuente() -> None:
    findings = [
        _gh("ana", _pivot("email", "info@ejemplo.com")),
        _f("harvested_email", "info@ejemplo.com", "theHarvester", 0.7),
    ]
    relations = correlate(Target(username="ana", domain="ejemplo.com"), findings)
    assert {"domain:ejemplo.com", "profile:https://github.com/ana"} <= {
        r.source for r in relations if r.target == "email:info@ejemplo.com"
    }


def test_perfil_de_otra_red_con_url_canonica_igual_se_une_a_la_cuenta_declarada() -> None:
    findings = [
        _gh("ana", _pivot("account", "twitter:ana")),
        _f("profile", "https://x.com/Ana", "WhatsMyName", 0.5),
        _f("profile", "https://reddit.com/user/ana", "WhatsMyName", 0.5),
    ]
    relations = correlate(Target(username="ana"), findings)
    assert ("profile:https://x.com/Ana", "account:twitter:ana") in _pairs(relations)
    assert not any(
        r.source == "profile:https://reddit.com/user/ana" and r.target.startswith("account:")
        for r in relations
    )


def test_sin_cuenta_declarada_no_se_crean_nodos_de_cuenta() -> None:
    findings = [_f("profile", "https://x.com/ana", "WhatsMyName", 0.5)]
    assert not any(
        r.target.startswith("account:") for r in correlate(Target(username="ana"), findings)
    )


@pytest.mark.parametrize(
    "raw",
    [
        {"pivots": "texto"},
        {"pivots": [None, 3, {"kind": "otro", "value": "x", "explicit": True}]},
        {"pivots": [{"kind": "email", "value": "", "explicit": True}]},
    ],
)
def test_pivotes_mal_formados_se_ignoran(raw: dict[str, object]) -> None:
    finding = Finding(
        entity_type="public_profile",
        type="github_profile",
        value="https://github.com/ana",
        source="GitHub",
        raw=raw,
    )
    assert _pairs(correlate(Target(username="ana"), [finding])) == {
        ("username:ana", "profile:https://github.com/ana")
    }


def _wmn_profile(site_name: str, username: str) -> Finding:
    sites = {site.name: site for site in load_wmn_sites(WMN_PATH)}
    return _build_finding(sites[site_name], username, 200)


def test_el_puente_canonico_no_supera_la_confianza_de_la_declaracion() -> None:
    findings = [
        _gh("ana", _pivot("account", "twitter:ana")),
        _f("profile", "https://x.com/Ana", "X", 0.5),
    ]
    relations = correlate(Target(username="ana"), findings)
    bridge = next(r for r in relations if r.source == "profile:https://x.com/Ana")
    assert bridge.target == "account:twitter:ana"
    assert bridge.confidence == 0.6


def test_perfiles_reales_del_dataset_wmn_se_unen_a_la_cuenta_declarada() -> None:
    findings = [
        _gh("ana", _pivot("account", "twitter:ana")),
        _wmn_profile("X", "ana"),
    ]
    relations = correlate(Target(username="ana"), findings)
    assert ("profile:https://x.com/ana", "account:twitter:ana") in _pairs(relations)


def test_github_profile_y_usernames_comparten_nodo_para_la_misma_cuenta() -> None:
    # El dataset actual excluye GitHub por su `protection`; se usa su URL pretty tal cual.
    github = _gh("ana", _pivot("website", "https://ana.dev"))
    wmn = _f("profile", "https://github.com/ana", "GitHub (User)", 0.5)
    relations = correlate(Target(username="ana"), [github, wmn])
    own = [r for r in relations if r.target == "profile:https://github.com/ana"]
    assert len(own) == 1
    assert own[0].evidence == ("GitHub", "GitHub (User)")


def test_las_relaciones_con_pivotes_son_deterministas() -> None:
    findings = [
        _gh("ana", _pivot("website", "https://ana.dev"), _pivot("email", "ana@ejemplo.com")),
        _f("profile", "https://x.com/ana", "WhatsMyName", 0.5),
    ]
    assert correlate(Target(username="ana"), findings) == correlate(
        Target(username="ana"), list(reversed(findings))
    )
