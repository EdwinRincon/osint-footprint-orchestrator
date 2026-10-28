import json
import logging
from pathlib import Path
from typing import Any

import pytest
import requests

from osint_tool.config import Settings
from osint_tool.models import SourceCheckStatus, Target
from osint_tool.modules.usernames import (
    Site,
    UsernamesModule,
    default_sites,
    load_wmn_sites,
)
from osint_tool.registry import ModuleSkipped

SITES_DEMO = (
    Site("Uno", "https://uno.test/{username}"),
    Site("Dos", "https://dos.test/{username}"),
)
TARGET = Target(username="ana_perez")
LARGE_DATASET_SIZE = 300

Responses = dict[str, int | tuple[int, str] | Exception]


class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, responses: Responses) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        if isinstance(result, tuple):
            return FakeResponse(*result)
        return FakeResponse(result)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ningún test depende de las variables WMN del entorno de quien lo ejecuta."""
    monkeypatch.delenv("OSINT_WMN_FILE", raising=False)


def _module(
    responses: Responses, sites: tuple[Site, ...] | None = SITES_DEMO
) -> tuple[UsernamesModule, FakeSession]:
    session = FakeSession(responses)
    return UsernamesModule(session, sites), session  # type: ignore[arg-type]


def _wmn_file(tmp_path: Path) -> Path:
    base = {"e_code": 200, "e_string": "ok", "m_code": 404, "m_string": "no"}
    data = {
        "license": [],
        "authors": [],
        "sites": [
            {
                "name": "Bueno",
                "uri_check": "https://b.test/{account}",
                "uri_pretty": "https://b.test/u/{account}",
                "cat": "social",
                **base,
            },
            {"name": "Post", "uri_check": "https://p.test/api", "post_body": "{}", **base},
            {"name": "Caido", "uri_check": "https://c.test/{account}", "valid": False, **base},
            {
                "name": "Captcha",
                "uri_check": "https://k.test/{account}",
                "protection": ["captcha"],
                **base,
            },
            {"name": "Otra", "uri_check": "https://o.test/{account}", "cat": "music", **base},
            {"name": "SinCuenta", "uri_check": "https://x.test/fijo", **base},
        ],
    }
    path = tmp_path / "wmn.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_perfil_encontrado() -> None:
    module, _ = _module({"https://uno.test/ana_perez": 200, "https://dos.test/ana_perez": 404})

    output = module.run(TARGET)

    findings = output.findings
    assert len(findings) == 1
    f = findings[0]
    assert (f.value, f.source, f.entity_type, f.type) == (
        "https://uno.test/ana_perez",
        "Uno",
        "username",
        "profile",
    )
    assert f.source_url == f.value
    assert f.confidence == 0.5
    assert [check.status for check in output.source_checks] == [
        SourceCheckStatus.FOUND,
        SourceCheckStatus.NOT_FOUND,
    ]


def test_informa_progreso_a_medida_que_terminan_los_sitios() -> None:
    module, _ = _module(
        {"https://uno.test/ana_perez": 200, "https://dos.test/ana_perez": 404}
    )
    progress: list[tuple[int, int]] = []
    module.set_progress_callback(lambda current, total: progress.append((current, total)))

    module.run(TARGET)

    assert sorted(progress) == [(1, 2), (2, 2)]


def test_respuestas_no_concluyentes_no_son_hallazgos() -> None:
    module, _ = _module({"https://uno.test/ana_perez": 403, "https://dos.test/ana_perez": 429})

    output = module.run(TARGET)

    assert output.findings == []
    assert [check.status for check in output.source_checks] == [
        SourceCheckStatus.INCONCLUSIVE,
        SourceCheckStatus.INCONCLUSIVE,
    ]


def test_un_fallo_de_red_no_corta_los_demas() -> None:
    module, _ = _module(
        {
            "https://uno.test/ana_perez": requests.ConnectionError(),
            "https://dos.test/ana_perez": 200,
        }
    )

    output = module.run(TARGET)

    assert [f.source for f in output.findings] == ["Dos"]
    assert [check.status for check in output.source_checks] == [
        SourceCheckStatus.ERROR,
        SourceCheckStatus.FOUND,
    ]


def test_no_sigue_redirecciones() -> None:
    module, session = _module(
        {"https://uno.test/ana_perez": 404, "https://dos.test/ana_perez": 404}
    )

    module.run(TARGET)

    assert len(session.calls) == 2
    assert all(kwargs["allow_redirects"] is False for _, kwargs in session.calls)


def test_sin_username_no_consulta_nada() -> None:
    module, session = _module({})

    output = module.run(Target(domain="ejemplo.com"))

    assert output.findings == []
    assert output.source_checks == []
    assert session.calls == []


def test_decide_por_el_texto_cuando_el_codigo_no_basta() -> None:
    def site(host: str) -> Site:
        return Site(
            host,
            f"https://{host}.test/{{username}}",
            e_code=200,
            e_string="registered_at",
            m_code=200,
            m_string="not_found",
        )

    module, _ = _module(
        {
            "https://existe.test/ana_perez": (200, '{"registered_at": 1}'),
            "https://no-existe.test/ana_perez": (200, '{"error": "not_found"}'),
            "https://raro.test/ana_perez": (200, "otra cosa"),
        },
        sites=(site("existe"), site("no-existe"), site("raro")),
    )

    assert [f.source for f in module.run(TARGET).findings] == ["existe"]


def test_url_con_llaves_no_rompe() -> None:
    site = Site("Api", "https://api.test/{username}?q={x}")
    module, _ = _module({"https://api.test/ana_perez?q={x}": 200}, sites=(site,))

    assert len(module.run(TARGET).findings) == 1


def test_usa_la_url_legible_como_valor() -> None:
    site = Site("Api", "https://api.test/u/{username}", pretty_url="https://web.test/{username}")
    module, _ = _module({"https://api.test/u/ana_perez": 200}, sites=(site,))

    assert [f.value for f in module.run(TARGET).findings] == ["https://web.test/ana_perez"]


def test_quita_los_caracteres_no_admitidos() -> None:
    site = Site("Solo", "https://solo.test/{username}", strip_chars=".")
    module, session = _module({"https://solo.test/anaperez": 404}, sites=(site,))

    module.run(Target(username="ana.perez"))

    assert [url for url, _ in session.calls] == ["https://solo.test/anaperez"]


def test_carga_wmn_y_filtra_entradas(tmp_path: Path) -> None:
    path = _wmn_file(tmp_path)

    sites = load_wmn_sites(path)

    assert [s.name for s in sites] == ["Bueno", "Otra"]
    assert sites[0].url == "https://b.test/{username}"
    assert sites[0].pretty_url == "https://b.test/u/{username}"
    assert sites[0].e_string == "ok"


def test_carga_cientos_de_sitios_desde_el_dataset(tmp_path: Path) -> None:
    entries = [
        {"name": f"S{i}", "uri_check": f"https://s{i}.test/{{account}}"}
        for i in range(LARGE_DATASET_SIZE)
    ]
    path = tmp_path / "grande.json"
    path.write_text(json.dumps({"sites": entries}), encoding="utf-8")

    assert len(load_wmn_sites(path)) == LARGE_DATASET_SIZE


def test_wmn_invalido(tmp_path: Path) -> None:
    lista = tmp_path / "lista.json"
    lista.write_text("[]", encoding="utf-8")
    roto = tmp_path / "roto.json"
    roto.write_text("{no es json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_wmn_sites(lista)
    with pytest.raises(ValueError):
        load_wmn_sites(roto)
    with pytest.raises(OSError):
        load_wmn_sites(tmp_path / "no-existe.json")


def test_sitios_por_defecto_vienen_del_dataset_configurado(tmp_path: Path) -> None:
    sites = default_sites(Settings(wmn_file=_wmn_file(tmp_path)))

    assert [s.name for s in sites] == ["Bueno", "Otra"]


def test_dataset_excluye_nsfw_de_forma_consistente(tmp_path: Path) -> None:
    path = _wmn_file(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["sites"].append(
        {
            "name": "Adulto",
            "uri_check": "https://adult.test/{account}",
            "cat": "xx NSFW xx",
            "e_code": 200,
            "e_string": "yes",
            "m_code": 404,
            "m_string": "no",
        }
    )
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded_sites = load_wmn_sites(path)
    default_sites_result = default_sites(Settings(wmn_file=path))

    assert [site.name for site in loaded_sites] == ["Bueno", "Otra"]
    assert [site.name for site in default_sites_result] == ["Bueno", "Otra"]


def test_sin_dataset_se_omite_con_un_mensaje_claro(tmp_path: Path) -> None:
    with pytest.raises(ModuleSkipped, match="WhatsMyName"):
        default_sites(Settings(wmn_file=tmp_path / "no-existe.json"))


def test_el_modulo_se_omite_si_el_dataset_del_entorno_no_existe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OSINT_WMN_FILE", str(tmp_path / "no-existe.json"))
    module, session = _module({}, sites=None)

    with pytest.raises(ModuleSkipped):
        module.run(TARGET)

    assert session.calls == []


def test_el_modulo_usa_el_dataset_del_entorno(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OSINT_WMN_FILE", str(_wmn_file(tmp_path)))
    module, _ = _module(
        {
            "https://b.test/ana_perez": (200, "ok"),
            "https://o.test/ana_perez": (404, "no"),
        },
        sites=None,
    )

    output = module.run(TARGET)

    assert [f.value for f in output.findings] == ["https://b.test/u/ana_perez"]
    assert [check.source for check in output.source_checks] == ["Bueno", "Otra"]


def test_resumen_de_sitios_inconclusos_sin_datos_personales(
    caplog: pytest.LogCaptureFixture,
) -> None:
    module, _ = _module({"https://uno.test/ana_perez": 403, "https://dos.test/ana_perez": 200})

    with caplog.at_level(logging.WARNING):
        module.run(TARGET)

    assert "1 de 2 sitios sin respuesta concluyente" in caplog.text
    assert "ana_perez" not in caplog.text