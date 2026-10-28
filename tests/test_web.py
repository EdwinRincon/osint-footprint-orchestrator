import json
import re
import threading
import time
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from osint_tool.models import (
    Finding,
    ModuleResult,
    Relation,
    Report,
    SourceCheck,
    SourceCheckStatus,
    Status,
    Target,
)
from osint_tool.web import app as webapp

JOB_URL = re.compile(r"^/jobs/[A-Za-z0-9_-]+$")
NO_MODULES_TEXT = "No hay fuentes habilitadas"


def _fake_investigation(
    target, modules=None, on_progress=None, on_module_progress=None
):  # type: ignore[no-untyped-def]
    finding = Finding(
        entity_type="domain", type="subdomain", value="a.ejemplo.com", source="Fake"
    )
    results = [ModuleResult("domain", Status.OK, [finding])]
    if on_module_progress:
        on_module_progress("domain", 0, 0)
    if on_progress:
        on_progress(results[0], 1, 1)
    return Report(target=target, results=results)


def _wait_for_completion(client: FlaskClient, job_url: str) -> dict:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        response = client.get(f"{job_url}/status")
        assert response.status_code == 200
        status = response.get_json()
        if status["status"] in {"complete", "failed"}:
            return status
        time.sleep(0.01)
    raise AssertionError("La investigación en segundo plano no terminó a tiempo")


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
    assert response.data.index(b'id="name"') < response.data.index(b'id="email"')
    assert response.data.index(b'id="email"') < response.data.index(b'id="analysis-title"')
    assert response.data.index(b'class="actions"') < response.data.index(
        b'id="analysis-title"'
    )
    assert b'input[type="email"]' in response.data
    assert b'input[type="tel"]' in response.data
    assert b'id="phone_region"' in response.data
    assert b"grid-template-columns: repeat(2, minmax(0, 1fr))" in response.data
    assert b".field-grid, .analysis-list { grid-template-columns: 1fr;" in response.data
    assert b'type="email"' in response.data
    assert b'type="tel"' in response.data
    assert b'id="source-settings-summary"' in response.data
    assert b"Datos que puede recibir:" in response.data
    assert b"WhatsMyName" in response.data
    assert b"Uso responsable" in response.data
    assert b"theHarvester" in response.data
    assert b"DNS y WHOIS" in response.data
    assert b"Perfiles de username" in response.data
    assert b"Iniciar an\xc3\xa1lisis" in response.data
    assert b'class="source-settings"' in response.data
    assert b"Modo privado: no permitir consultas externas" in response.data
    assert b"@media (max-width: 680px)" in response.data
    assert re.search(rb'<input id="offline"[^>]*checked', response.data, re.DOTALL)
    assert b'data-network="true"' in response.data
    for module_name in (b"breaches", b"domain", b"harvester", b"usernames"):
        assert not re.search(
            rb'<input id="module-' + module_name + rb'"[^>]*checked', response.data
        )


def test_busqueda_es_asincrona_y_no_genera_informe_automaticamente(
    client: FlaskClient, salida: Path
) -> None:
    response = client.post(
        "/", data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]}
    )
    assert response.status_code == 303
    job_url = response.headers["Location"]
    assert JOB_URL.match(job_url)
    assert b"Progreso y resultados" in client.get(job_url).data
    assert _wait_for_completion(client, job_url)["status"] == "complete"

    data = client.get(f"{job_url}/data")
    assert data.status_code == 200
    assert data.get_json()["findings"] == 1
    assert data.get_json()["finding_items"][0]["value"] == "a.ejemplo.com"
    assert data.get_json()["relation_items"] == []
    assert list(salida.glob("*/report.html")) == []

    generated = client.post(
        f"{job_url}/report",
        data={"statuses": ["found", "not_found", "inconclusive", "error"]},
    )
    assert generated.status_code == 200
    generated_payload = generated.get_json()
    report_url = generated_payload["report_url"]
    assert report_url.startswith("/reports/")
    assert b"Informe OSINT" in client.get(report_url).data
    download_urls = generated_payload["download_urls"]
    assert download_urls["report.html"] == report_url
    assert generated_payload["graph_url"]
    assert client.get(generated_payload["graph_url"]).status_code == 200
    assert b"Grafo interactivo" not in client.get(report_url).data
    report_json = client.get(download_urls["report.json"])
    assert report_json.status_code == 200
    assert report_json.mimetype == "application/json"
    assert len(list(salida.glob("*/report.html"))) == 1


@pytest.mark.parametrize("name", ["Edwin Rincon Cardona", "Edwin", "Edwin Rincon"])
def test_entradas_combinadas_llegan_al_informe_sin_consultas_reales(
    name: str, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[Target] = []

    def fake_investigation(target, modules=None, **_callbacks):  # type: ignore[no-untyped-def]
        observed.append(target)
        return _fake_investigation(target, modules)

    monkeypatch.setattr(webapp, "run_investigation", fake_investigation)
    selected_sources = [
        module
        for module, _ in webapp.web_network_modules()
        if module != "harvester"
    ]
    response = client.post(
        "/",
        data={
            "name": name,
            "email": "rinconedwin@example.test",
            "username": "erinconc",
            "phone": "642775948",
            "phone_region": "ES",
            "domain": "example.com",
            "offline": "",
            "modules": selected_sources,
        },
    )
    assert response.status_code == 303
    job_url = response.headers["Location"]
    assert _wait_for_completion(client, job_url)["status"] == "complete"
    assert observed[0].to_dict() == {
        "email": "rinconedwin@example.test",
        "username": "erinconc",
        "domain": "example.com",
        "phone": "+34642775948",
        "name": name,
    }

    generated = client.post(
        f"{job_url}/report",
        data={"statuses": ["found", "not_found", "inconclusive", "error"]},
    )
    assert generated.status_code == 200
    report_json = client.get(generated.get_json()["download_urls"]["report.json"])
    assert report_json.status_code == 200
    assert report_json.get_json()["target"] == observed[0].to_dict()
    report_html = client.get(generated.get_json()["report_url"])
    assert report_html.status_code == 200
    assert b"Informe OSINT" in report_html.data


def test_resultados_incluyen_descargas_html_y_json(client: FlaskClient) -> None:
    response = client.post(
        "/", data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]}
    )
    results_page = client.get(response.headers["Location"]).data

    assert results_page.index(b'id="generate-report"') < results_page.index(
        b'id="findings-title"'
    )
    assert results_page.index(b'id="report-ready"') < results_page.index(
        b'id="findings-title"'
    )
    assert b'id="report-download-html"' in results_page
    assert b'id="report-download-json"' in results_page
    assert b'id="relations-load-more"' in results_page
    assert b'id="graph-link"' in results_page
    assert b'download>' in results_page
    assert b"PDF no disponible" in results_page
    assert b'Tabla de hallazgos; desplazamiento horizontal' in results_page
    assert b"Desliza la tabla horizontalmente" in results_page


def test_filtros_de_estado_iniciales(client: FlaskClient) -> None:
    response = client.post(
        "/", data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]}
    )
    results_page = client.get(response.headers["Location"]).data

    inputs = re.findall(
        rb'<input type="checkbox" name="statuses" value="([^"]+)"([^>]*)>',
        results_page,
    )
    assert {value for value, _ in inputs} == {
        b"found", b"not_found", b"inconclusive", b"error"
    }
    assert {value for value, attrs in inputs if b"checked" in attrs} == {b"found"}


def test_progreso_de_modulos_se_exhibe_durante_la_busqueda(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    finish = threading.Event()

    def slow_investigation(target, modules, on_progress, on_module_progress):
        on_module_progress("usernames", 0, 10)
        on_module_progress("usernames", 3, 10)
        started.set()
        assert finish.wait(timeout=2)
        result = ModuleResult("usernames", Status.OK)
        on_progress(result, 1, 1)
        return Report(target=target, results=[result])

    monkeypatch.setattr(webapp, "run_investigation", slow_investigation)
    response = client.post(
        "/", data={"username": "demo_user", "offline": "", "modules": ["usernames"]}
    )
    job_url = response.headers["Location"]
    assert started.wait(timeout=1)
    status = client.get(f"{job_url}/status").get_json()
    assert status["current_module"] == "usernames"
    assert (status["current_completed"], status["current_total"]) == (3, 10)

    finish.set()
    assert _wait_for_completion(client, job_url)["status"] == "complete"


def test_busqueda_por_nombre_no_inicia_una_investigacion_sin_fuentes(
    real_client: FlaskClient,
) -> None:
    response = real_client.post("/", data={"name": "Ana Pérez"})
    assert response.status_code == 200
    assert NO_MODULES_TEXT in response.data.decode()
    assert "desmarca «Modo privado»" in response.data.decode()
    assert "Perfiles de GitHub por nombre" in response.data.decode()
    assert not real_client.application.extensions["osint_jobs"]._jobs


def test_busqueda_por_nombre_permite_opt_in_de_wikidata(
    real_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected: list[str] = []

    def no_modules(target, names=None):
        selected.extend(names or [])
        return []

    monkeypatch.setattr(webapp, "applicable_modules", no_modules)
    response = real_client.post(
        "/",
        data={"name": "Ana Pérez", "offline": "", "modules": ["wikidata"]},
    )

    assert response.status_code == 200
    assert "wikidata" in selected
    assert "Datos que puede recibir:" in response.data.decode()


def test_busqueda_offline_no_incluye_modulos_de_red(
    real_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected: list[str] = []

    def no_local_modules(target, names=None):
        selected.extend(names or [])
        return []

    monkeypatch.setattr(webapp, "applicable_modules", no_local_modules)
    response = real_client.post(
        "/",
        data={
            "domain": "ejemplo.com",
            "email": "ana@ejemplo.com",
            "offline": "on",
            "modules": ["domain", "breaches"],
        },
    )

    assert response.status_code == 200
    assert selected == ["phone"]
    assert NO_MODULES_TEXT in response.data.decode()


def test_fuente_de_red_requiere_opt_in_individual(
    real_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected: list[str] = []

    def no_modules(target, names=None):
        selected.extend(names or [])
        return []

    monkeypatch.setattr(webapp, "applicable_modules", no_modules)
    response = real_client.post(
        "/", data={"email": "ana@ejemplo.com", "modules": ["breaches"]}
    )

    assert response.status_code == 200
    assert "breaches" in selected
    assert "usernames" not in selected
    assert "domain" not in selected


def test_email_de_brechas_explica_tercero_y_limites(client: FlaskClient) -> None:
    response = client.get("/")

    assert b"25/hora" in response.data
    assert b"100/d\xc3\xada" in response.data
    assert b"El correo se env\xc3\xada" in response.data


def test_informe_filtra_comprobaciones_y_conserva_cobertura_completa(
    client: FlaskClient, salida: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = Finding(
        entity_type="username",
        type="profile",
        value="https://site-a.test/demo",
        source="Site A",
        source_url="https://site-a.test/demo",
        confidence=0.5,
    )
    second = Finding(
        entity_type="username",
        type="profile",
        value="https://site-b.test/demo",
        source="Site B",
        source_url="https://site-b.test/demo",
        confidence=0.5,
    )
    result = ModuleResult(
        "usernames",
        Status.OK,
        [first, second],
        source_checks=[
            SourceCheck("Site A", SourceCheckStatus.FOUND, "HTTP 200"),
            SourceCheck("Site B", SourceCheckStatus.NOT_FOUND, "HTTP 404"),
            SourceCheck("Site C", SourceCheckStatus.INCONCLUSIVE, "HTTP 429"),
        ],
    )
    source_reports: list[Report] = []

    def fake_investigation(target, modules, on_progress, on_module_progress):
        report = Report(target=target, results=[result])
        source_reports.append(report)
        return report

    monkeypatch.setattr(webapp, "run_investigation", fake_investigation)

    job_url = client.post(
        "/", data={"username": "demo_user", "offline": "", "modules": ["usernames"]}
    ).headers["Location"]
    assert _wait_for_completion(client, job_url)["status"] == "complete"
    response = client.get(f"{job_url}/data")
    checks = response.get_json()["source_checks"]
    assert len(checks) == 3
    assert checks[0]["profile_url"] == "https://site-a.test/demo"
    assert list(salida.iterdir()) == []

    generated = client.post(
        f"{job_url}/report", data={"statuses": ["found"], "query": "site a"}
    )
    assert generated.status_code == 200
    report_url = generated.get_json()["report_url"]
    report_json = json.loads(
        client.get(report_url.replace("report.html", "report.json")).data
    )
    usernames = report_json["results"][0]
    assert [item["source"] for item in usernames["findings"]] == ["Site A"]
    assert [item["source"] for item in usernames["source_checks"]] == ["Site A"]
    assert report_json["coverage_summary"] == {
        "total": 3,
        "included": 1,
        "found": 1,
        "not_found": 1,
        "inconclusive": 1,
        "error": 0,
    }
    assert report_json["filter_summary"] == {"statuses": "found", "search": "site a"}
    assert len(report_json["notes"]) == 1

    generated_again = client.post(
        f"{job_url}/report", data={"statuses": ["found"], "query": "site a"}
    )
    report_again = json.loads(
        client.get(
            generated_again.get_json()["report_url"].replace("report.html", "report.json")
        ).data
    )
    assert report_again["notes"] == report_json["notes"]
    assert source_reports[0].notes == []


def test_informe_filtra_por_modulo_y_recalcula_relaciones(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    username_finding = Finding(
        entity_type="username",
        type="profile",
        value="https://site.test/demo",
        source="Site",
        confidence=0.5,
    )
    phone_finding = Finding(
        entity_type="phone",
        type="phone_region",
        value="ES",
        source="Phone",
    )
    report = Report(
        target=Target(username="demo", phone="+34600000000"),
        results=[
            ModuleResult(
                "usernames",
                Status.OK,
                [username_finding],
                source_checks=[SourceCheck("Site", SourceCheckStatus.FOUND)],
            ),
            ModuleResult("phone", Status.OK, [phone_finding]),
        ],
        relations=[
            Relation("username:demo", "profile:https://site.test/demo", "perfil", 0.5),
            Relation("phone:+34600000000", "region:ES", "región", 1.0),
        ],
    )
    monkeypatch.setattr(webapp, "run_investigation", lambda *args, **kwargs: report)

    job_url = client.post(
        "/",
        data={
            "username": "demo",
            "phone": "+34600000000",
            "offline": "",
            "modules": ["usernames"],
        },
    ).headers["Location"]
    assert _wait_for_completion(client, job_url)["status"] == "complete"

    data = client.get(f"{job_url}/data").get_json()
    assert [finding["module"] for finding in data["finding_items"]] == ["usernames", "phone"]
    assert len(data["relation_items"]) == 2

    generated = client.post(
        f"{job_url}/report",
        data={"statuses": ["found"], "module": "phone"},
    )
    assert generated.status_code == 200
    generated_payload = generated.get_json()
    report_url = generated_payload["report_url"]
    assert generated_payload["graph_url"]
    assert client.get(generated_payload["graph_url"]).status_code == 200
    assert b"Grafo interactivo" not in client.get(report_url).data
    report_json = json.loads(
        client.get(report_url.replace("report.html", "report.json")).data
    )
    assert [result["name"] for result in report_json["results"]] == ["phone"]
    assert [relation["source"] for relation in report_json["relations"]] == [
        "phone:+34600000000"
    ]
    assert report_json["filter_summary"]["module"] == "phone"


def test_dns_y_whois_aparecen_en_cobertura_y_se_filtran(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    dns_finding = Finding(
        entity_type="domain",
        type="dns_record",
        value="A 192.0.2.10",
        source="DNS",
        raw={"record_type": "A"},
    )
    whois_finding = Finding(
        entity_type="domain",
        type="whois_registrar",
        value="Example Registrar",
        source="WHOIS",
    )
    result = ModuleResult(
        "domain",
        Status.OK,
        [dns_finding, whois_finding],
        source_checks=[
            SourceCheck("DNS A", SourceCheckStatus.FOUND),
            SourceCheck("DNS AAAA", SourceCheckStatus.NOT_FOUND),
            SourceCheck("WHOIS", SourceCheckStatus.ERROR, "Timeout"),
        ],
    )
    report = Report(target=Target(domain="example.test"), results=[result])
    monkeypatch.setattr(webapp, "run_investigation", lambda *args, **kwargs: report)

    job_url = client.post(
        "/", data={"domain": "example.test", "offline": "", "modules": ["domain"]}
    ).headers["Location"]
    assert _wait_for_completion(client, job_url)["status"] == "complete"
    data = client.get(f"{job_url}/data").get_json()
    assert [check["source"] for check in data["source_checks"]] == [
        "DNS A",
        "DNS AAAA",
        "WHOIS",
    ]
    assert [finding["source"] for finding in data["finding_items"]] == ["DNS", "WHOIS"]

    generated = client.post(
        f"{job_url}/report",
        data={"statuses": ["found"], "module": "domain", "query": "DNS"},
    )
    assert generated.status_code == 200
    report_json = json.loads(
        client.get(
            generated.get_json()["report_url"].replace("report.html", "report.json")
        ).data
    )
    domain = report_json["results"][0]
    assert [finding["value"] for finding in domain["findings"]] == ["A 192.0.2.10"]
    assert [check["source"] for check in domain["source_checks"]] == ["DNS A"]
    assert report_json["coverage_summary"] == {
        "total": 3,
        "included": 1,
        "found": 1,
        "not_found": 1,
        "inconclusive": 0,
        "error": 1,
    }


def test_error_de_busqueda_en_segundo_plano_se_muestra(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed(*args, **kwargs):
        raise RuntimeError("dato privado")

    monkeypatch.setattr(webapp, "run_investigation", failed)
    job_url = client.post(
        "/", data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]}
    ).headers["Location"]
    status = _wait_for_completion(client, job_url)
    assert status["status"] == "failed"
    assert "dato privado" not in status["error"]


def test_se_rechazan_modulos_opcionales_desconocidos(
    client: FlaskClient, salida: Path
) -> None:
    response = client.post("/", data={"domain": "ejemplo.com", "modules": "unknown"})
    assert response.status_code == 400
    assert b"selecci\xc3\xb3n de herramientas" in response.data.lower()
    assert list(salida.iterdir()) == []


def test_dato_invalido_devuelve_400_y_no_escribe_nada(
    client: FlaskClient, salida: Path
) -> None:
    response = client.post("/", data={"domain": "a..com"})
    assert response.status_code == 400
    assert "dominio no válido".encode() in response.data
    assert list(salida.iterdir()) == []


def test_sin_datos_devuelve_400(client: FlaskClient) -> None:
    response = client.post("/", data={})
    assert response.status_code == 400
    assert b"al menos un dato" in response.data


def test_valor_enviado_se_escapa_en_el_formulario(client: FlaskClient) -> None:
    response = client.post("/", data={"email": '"><script>alert(1)</script>'})
    assert response.status_code == 400
    assert b"<script>" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_solo_se_sirven_ficheros_de_informe_permitidos(
    client: FlaskClient, salida: Path
) -> None:
    run = salida / "20261013T184631-5d935f"
    run.mkdir()
    (run / "secreto.txt").write_text("no debe verse")
    assert client.get("/reports/abc/report.html").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/secreto.txt").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/report.html").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/graph.png").status_code == 404
    assert client.get("/reports/20261013T184631-5d935f/graph.dot").status_code == 404


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
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "same-origin"
    assert headers["Cache-Control"] == "no-store"


def test_informes_no_se_guardan_en_cache(client: FlaskClient) -> None:
    job_url = client.post(
        "/", data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]}
    ).headers["Location"]
    assert client.get(job_url).headers["Cache-Control"] == "no-store"


def test_origin_propio_se_acepta(client: FlaskClient) -> None:
    response = client.post(
        "/",
        data={"domain": "ejemplo.com", "offline": "", "modules": ["domain"]},
        headers={"Origin": "http://localhost"},
    )
    assert response.status_code == 303


def test_origin_null_se_rechaza(client: FlaskClient, salida: Path) -> None:
    response = client.post("/", data={"domain": "ejemplo.com"}, headers={"Origin": "null"})
    assert response.status_code == 403
    assert list(salida.iterdir()) == []
