from typing import Any

import pytest
import requests

from osint_tool.correlator import correlate
from osint_tool.models import ModuleResult, Report, SourceCheckStatus, Status, Target
from osint_tool.modules import github_names, github_profile
from osint_tool.modules.github_profile import GitHubProfileModule
from osint_tool.registry import applicable_modules
from osint_tool.web.app import _filter_report

PAYLOAD = {
    "login": "Ana",
    "blog": "https://www.ana.dev/",
    "twitter_username": "AnaDev",
    "email": "ana@ejemplo.com",
    "location": "Madrid",
    "company": "@acme",
    "gravatar_id": "",
}


class FakeResponse:
    def __init__(
        self, status_code: int, payload: Any, headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self.payload = payload
        self.headers = headers or {}

    def json(self) -> Any:
        return self.payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        return self.response


def _module(response: FakeResponse) -> tuple[GitHubProfileModule, FakeSession]:
    session = FakeSession(response)
    return GitHubProfileModule(session), session  # type: ignore[arg-type]


def test_se_registra_como_fuente_de_red_para_username() -> None:
    modules = applicable_modules(Target(username="ana"))
    module = next(m for m in modules if m.name == "github_profile")
    assert module.requires_network is True
    assert applicable_modules(Target(name="Ana Pérez"), ["github_profile"]) == []


def test_consulta_una_vez_el_perfil_y_extrae_pivotes() -> None:
    module, session = _module(FakeResponse(200, PAYLOAD))

    output = module.run(Target(username="ana"))

    assert [url for url, _ in session.calls] == ["https://api.github.com/users/ana"]
    assert session.calls[0][1]["headers"]["X-GitHub-Api-Version"] == "2026-03-10"
    finding = output.findings[0]
    assert (finding.type, finding.value, finding.source) == (
        "github_profile",
        "https://github.com/ana",
        "GitHub",
    )
    assert finding.raw["pivots"] == [
        {"kind": "website", "value": "https://ana.dev", "explicit": True},
        {"kind": "account", "value": "twitter:anadev", "explicit": True},
        {"kind": "email", "value": "ana@ejemplo.com", "explicit": True},
    ]
    assert "ana@ejemplo.com" not in (finding.detail or "")
    assert output.source_checks[0].status is SourceCheckStatus.FOUND


def test_no_visita_la_web_declarada() -> None:
    module, session = _module(FakeResponse(200, PAYLOAD))
    module.run(Target(username="ana"))
    assert all(url.startswith("https://api.github.com/") for url, _ in session.calls)


@pytest.mark.parametrize("username", ["_ana", "ana.dev", "ana_dev", "-ana", "ana-"])
def test_formato_no_valido_para_github_no_usa_la_red(username: str) -> None:
    module, session = _module(FakeResponse(200, PAYLOAD))

    output = module.run(Target(username=username))

    assert session.calls == []
    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.NOT_FOUND


def test_perfil_inexistente_es_not_found() -> None:
    module, _ = _module(FakeResponse(404, {}))
    output = module.run(Target(username="ana"))
    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.NOT_FOUND


@pytest.mark.parametrize(
    ("status_code", "headers"), [(403, {"X-RateLimit-Remaining": "0"}), (429, {})]
)
def test_limite_de_uso_es_inconcluso(status_code: int, headers: dict[str, str]) -> None:
    module, _ = _module(FakeResponse(status_code, {}, headers))
    output = module.run(Target(username="ana"))
    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.INCONCLUSIVE


def test_otro_403_es_un_error() -> None:
    module, _ = _module(FakeResponse(403, {}, {"X-RateLimit-Remaining": "5"}))
    with pytest.raises(requests.HTTPError):
        module.run(Target(username="ana"))


@pytest.mark.parametrize("payload", [[], {}, {"login": 3}, {"login": "otra-persona"}])
def test_respuesta_malformada_lanza_error(payload: Any) -> None:
    module, _ = _module(FakeResponse(200, payload))
    with pytest.raises(ValueError, match="Respuesta de GitHub no válida"):
        module.run(Target(username="ana"))


def test_no_consulta_sin_username() -> None:
    module, session = _module(FakeResponse(200, PAYLOAD))
    assert module.run(Target(name="Ana")).findings == []
    assert session.calls == []


def test_ambos_modulos_de_github_comparten_el_patron_de_login() -> None:
    assert github_names.LOGIN_PATTERN is github_profile.LOGIN_PATTERN


def test_el_perfil_enlaza_con_sus_pivotes_en_el_grafo() -> None:
    module, _ = _module(FakeResponse(200, PAYLOAD))
    findings = module.run(Target(username="Ana")).findings

    pairs = {(r.source, r.target): r for r in correlate(Target(username="Ana"), findings)}

    profile = "profile:https://github.com/Ana"
    assert ("username:Ana", profile) in pairs
    assert pairs[(profile, "website:https://ana.dev")].confidence == 0.6
    assert (profile, "account:twitter:anadev") in pairs
    assert (profile, "email:ana@ejemplo.com") in pairs
    assert not any("Madrid" in key or "acme" in key for pair in pairs for key in pair)


def test_la_informacion_se_conserva_al_filtrar_el_informe() -> None:
    module, _ = _module(FakeResponse(200, PAYLOAD))
    target = Target(username="Ana")
    result = ModuleResult("github_profile", Status.OK, module.run(target).findings)
    report = Report(target=target, results=[result], relations=correlate(target, result.findings))

    filtered = _filter_report(report, set(), "github", "github_profile")

    assert filtered.relations == report.relations
