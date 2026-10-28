from typing import Any

import pytest
import requests

from osint_tool.models import SourceCheckStatus, Target
from osint_tool.modules.wikidata import WikidataModule
from osint_tool.registry import applicable_modules

NAME = "Ada Lovelace"
PAYLOAD = {
    "search": [
        {
            "id": "Q7259",
            "label": "Ada Lovelace",
            "description": "English mathematician (1815-1852)",
        },
        {"id": "Q114068528", "label": "Ada Lovelace", "description": "GPU microarchitecture"},
    ]
}


class FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self.payload = payload

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


def test_busqueda_por_nombre_se_registra_como_fuente_externa() -> None:
    modules = applicable_modules(Target(name=NAME))

    names = {module.name for module in modules}
    assert {"github_name", "wikidata"} <= names
    assert "usernames" not in names
    assert all(module.requires_network for module in modules)


def test_devuelve_hasta_cinco_coincidencias_con_fuente_y_nota_de_cautela() -> None:
    session = FakeSession(FakeResponse(200, PAYLOAD))
    module = WikidataModule(session)  # type: ignore[arg-type]

    output = module.run(Target(name=NAME))

    assert len(output.findings) == 2
    finding = output.findings[0]
    assert (finding.value, finding.source, finding.type, finding.confidence) == (
        NAME,
        "Wikidata",
        "name_candidate",
        0.2,
    )
    assert finding.source_url == "https://www.wikidata.org/wiki/Q7259"
    assert "no confirma identidad" in (finding.detail or "")
    assert output.source_checks[0].status is SourceCheckStatus.FOUND
    assert session.calls == [
        (
            "https://www.wikidata.org/w/api.php",
            {
                "params": {
                    "action": "wbsearchentities",
                    "format": "json",
                    "search": NAME,
                    "language": "es",
                    "uselang": "es",
                    "type": "item",
                    "limit": 5,
                }
            },
        )
    ]


def test_sin_resultados_es_not_found() -> None:
    module = WikidataModule(FakeSession(FakeResponse(200, {"search": []})))  # type: ignore[arg-type]

    output = module.run(Target(name=NAME))

    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.NOT_FOUND


def test_limite_de_peticiones_es_inconcluso() -> None:
    module = WikidataModule(FakeSession(FakeResponse(429, {})))  # type: ignore[arg-type]

    output = module.run(Target(name=NAME))

    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.INCONCLUSIVE


def test_limite_reportado_en_respuesta_json_es_inconcluso() -> None:
    module = WikidataModule(
        FakeSession(FakeResponse(200, {"error": {"code": "ratelimited"}}))  # type: ignore[arg-type]
    )

    output = module.run(Target(name=NAME))

    assert output.findings == []
    assert output.source_checks[0].status is SourceCheckStatus.INCONCLUSIVE


def test_entrada_malformada_no_se_informa_como_sin_coincidencias() -> None:
    module = WikidataModule(
        FakeSession(FakeResponse(200, {"search": [{"id": "invalid"}]}))  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="Respuesta de Wikidata no válida"):
        module.run(Target(name=NAME))


def test_no_consulta_si_el_nombre_no_esta_presente() -> None:
    session = FakeSession(FakeResponse(200, PAYLOAD))
    module = WikidataModule(session)  # type: ignore[arg-type]

    output = module.run(Target(domain="example.test"))

    assert output.findings == []
    assert output.source_checks == []
    assert session.calls == []
