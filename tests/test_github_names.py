from typing import Any

import pytest
import requests

from osint_tool.models import SourceCheckStatus, Target
from osint_tool.modules.github_names import GitHubNameModule
from osint_tool.registry import applicable_modules

NAME = "Ada Lovelace"
PAYLOAD = {
    "total_count": 2,
    "incomplete_results": False,
    "items": [
        {"login": "ada-dev", "html_url": "https://github.com/ada-dev", "type": "User"},
        {"login": "lovelace", "html_url": "https://github.com/lovelace", "type": "User"},
    ],
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


def test_busqueda_por_nombre_se_registra_como_fuente_de_red() -> None:
    modules = applicable_modules(Target(name=NAME))

    assert "github_name" in [module.name for module in modules]
    github_module = next(module for module in modules if module.name == "github_name")
    assert github_module.requires_network is True


def test_consulta_nombres_completos_y_devuelve_perfiles_como_candidatos() -> None:
    session = FakeSession(FakeResponse(200, PAYLOAD))
    module = GitHubNameModule(session)  # type: ignore[arg-type]

    output = module.run(Target(name=NAME))

    assert session.calls == [
        (
            "https://api.github.com/search/users",
            {
                "params": {"q": "Ada Lovelace in:fullname", "per_page": 5},
                "headers": {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
            },
        )
    ]
    assert [finding.value for finding in output.findings] == ["ada-dev", "lovelace"]
    finding = output.findings[0]
    assert (finding.source, finding.type, finding.confidence) == (
        "GitHub",
        "name_candidate",
        0.2,
    )
    assert finding.entity_type == "public_profile"
    assert finding.source_url == "https://github.com/ada-dev"
    assert "no confirma identidad" in (finding.detail or "")
    assert output.source_checks[0].status is SourceCheckStatus.FOUND


def test_limita_los_resultados_a_cinco() -> None:
    payload = {
        "total_count": 8,
        "items": [
            {"login": f"user-{index}", "html_url": f"https://github.com/user-{index}"}
            for index in range(8)
        ],
    }
    module = GitHubNameModule(FakeSession(FakeResponse(200, payload)))  # type: ignore[arg-type]

    assert len(module.run(Target(name=NAME)).findings) == 5


@pytest.mark.parametrize(
    ("status_code", "headers"),
    [(403, {"X-RateLimit-Remaining": "0"}), (429, {})],
)
def test_rate_limit_es_inconcluso(status_code: int, headers: dict[str, str]) -> None:
    module = GitHubNameModule(
        FakeSession(FakeResponse(status_code, {}, headers))  # type: ignore[arg-type]
    )

    output = module.run(Target(name=NAME))

    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.INCONCLUSIVE


def test_sin_resultados_es_not_found() -> None:
    module = GitHubNameModule(
        FakeSession(FakeResponse(200, {"total_count": 0, "items": []}))  # type: ignore[arg-type]
    )

    assert module.run(Target(name=NAME)).source_checks[0].status is SourceCheckStatus.NOT_FOUND


def test_no_consulta_si_no_hay_nombre() -> None:
    session = FakeSession(FakeResponse(200, PAYLOAD))
    module = GitHubNameModule(session)  # type: ignore[arg-type]

    output = module.run(Target(username="ada-dev"))

    assert output.findings == []
    assert output.source_checks == []
    assert session.calls == []


def test_respuesta_malformada_no_es_not_found() -> None:
    module = GitHubNameModule(
        FakeSession(FakeResponse(200, {"items": [{"login": "bad/login"}]}))  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="Respuesta de GitHub no válida"):
        module.run(Target(name=NAME))
