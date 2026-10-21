import json
import re
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from osint_tool.models import Finding, ModuleResult, Report, Status
from osint_tool.web import app as webapp

RUN_URL = re.compile(r"^/reports/\d{8}T\d{6}-[0-9a-f]{6}/report\.html$")
NO_MODULES_TEXT = "Ningún módulo acepta"


def _fake_investigation(target, modules=None):  # type: ignore[no-untyped-def]
    finding = Finding(
        entity_type="domain", type="subdomain", value="a.ejemplo.com", source="Fake"
    )
    return Report(target=target, results=[ModuleResult("domain", Status.OK, [finding])])


@pytest.fixture
def salida(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def client(salida: Path, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setattr(webapp, "run_investigation", _fake_investigation)
    return webapp.create_app(salida).test_client()


@pytest.fixture
def real_client(salida: Path) -> FlaskClient:
    """Cliente con el servicio real: sin módulos aplicables no hay red."""
    return webapp.create_app(salida).test_client()


def test_formulario_inicial(client: FlaskClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert b"<form" in response.data
    assert b"Uso responsable" in response.data
    assert b"theHarvester" in response.data
    assert b'type="checkbox"' in response.data


def test_busqueda_valida_redirige_al_informe(client: FlaskClient, salida: Path) -> None:
    response = client.post("/", data={"domain": "ejemplo.com"})
    assert response.status_code == 303
    location = response.headers["Location"]
    assert RUN_URL.match(location)

    report = client.get(location)
    assert report.status_code == 200
    assert b"Informe OSINT" in report.data
    assert len(list(salida.glob("*/report.html"))) == 1
    assert client.get(location.replace("report.html", "report.json")).status_code == 200


def test_busqueda_solo_por_nombre_avisa_de_que_no_se_consulto_ninguna_fuente(
    real_client: FlaskClient,
) -> None:
    response = real_client.post("/", data={"name": "Ana Pérez"})
    assert response.status_code == 303

    html = real_client.get(response.headers["Location"]).data.decode()

    assert NO_MODULES_TEXT in html


def test_el_aviso_de_sin_modulos_tambien_esta_en_el_json(
    real_client: FlaskClient,
) -> None:
    location = real_client.post("/", data={"name": "Ana Pérez"}).headers["Location"]

    data = json.loads(real_client.get(location.replace("report.html", "report.json")).data)

    assert len(data["notes"]) == 1
    assert NO_MODULES_TEXT in data["notes"][0]


def test_herramientas_opcionales_no_se_ejecutan_por_defecto(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    executed: list[str] = []

    def record_modules(target, modules=None):  # type: ignore[no-untyped-def]
        executed.extend(module.name for module in modules or [])
        return _fake_investigation(target, modules)

    monkeypatch.setattr(webapp, "run_investigation", record_modules)
    response = client.post("/", data={"domain": "ejemplo.com"})

    assert response.status_code == 303
    assert "domain" in executed
    assert "harvester" not in executed


def test_herramienta_opcional_se_ejecuta_si_se_selecciona(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    executed: list[str] = []

    def record_modules(target, modules=None):  # type: ignore[no-untyped-def]
        executed.extend(module.name for module in modules or [])
        return _fake_investigation(target, modules)

    monkeypatch.setattr(webapp, "run_investigation", record_modules)
    response = client.post("/", data={"domain": "ejemplo.com", "modules": "harvester"})

    assert response.status_code == 303
    assert "domain" in executed
    assert "harvester" in executed


def test_se_rechazan_modulos_opcionales_desconocidos(
    client: FlaskClient, salida: Path
) -> None:
    response = client.post("/", data={"domain": "ejemplo.com", "modules": "unknown"})

    assert response.status_code == 400
    assert b"selecci\xc3\xb3n de herramientas" in response.data.lower()
    assert list(salida.iterdir()) == []


def test_dato_invalido_devuelve_400_y_no_escribe_nada(client: FlaskClient, salida: Path) -> None:
    response = client.post("/", data={"domain": "a..com"})
    assert response.status_code == 400
    assert "dominio no válido".encode() in response.data
    assert list(salida.iterdir()) == []


def test_sin_datos_devuelve_400(client: FlaskClient) -> None:
    response = client.post("/", data={})
    assert response.status_code == 400
    assert b"al menos un dato" in response.data


def test_el_valor_enviado_se_escapa_en_el_formulario(client: FlaskClient) -> None:
    response = client.post("/", data={"email": '"><script>alert(1)</script>'})
    assert response.status_code == 400
    assert b"<script>" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_solo_se_sirven_carpetas_y_ficheros_permitidos(client: FlaskClient, salida: Path) -> None:
    run = salida / "20261013T184631-5d935f"
    run.mkdir()
    (run / "secreto.txt").write_text("no debe verse")
    assert client.get("/reports/abc/report.html").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/secreto.txt").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/report.html").status_code == 404


def test_host_ajeno_se_rechaza(client: FlaskClient) -> None:
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_origin_ajeno_en_post_se_rechaza(client: FlaskClient, salida: Path) -> None:
    response = client.post(
        "/", data={"domain": "ejemplo.com"}, headers={"Origin": "http://evil.example"}
    )
    assert response.status_code == 403
    assert list(salida.iterdir()) == []


def test_cabeceras_de_seguridad(client: FlaskClient) -> None:
    headers = client.get("/").headers
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "same-origin"
    assert headers["Cache-Control"] == "no-store"


def test_los_informes_no_se_guardan_en_la_cache_del_navegador(client: FlaskClient) -> None:
    location = client.post("/", data={"domain": "ejemplo.com"}).headers["Location"]

    assert client.get(location).headers["Cache-Control"] == "no-store"


def test_origin_propio_se_acepta(client: FlaskClient) -> None:
    response = client.post(
        "/", data={"domain": "ejemplo.com"}, headers={"Origin": "http://localhost"}
    )
    assert response.status_code == 303


def test_origin_null_se_rechaza(client: FlaskClient, salida: Path) -> None:
    response = client.post("/", data={"domain": "ejemplo.com"}, headers={"Origin": "null"})
    assert response.status_code == 403
    assert list(salida.iterdir()) == []