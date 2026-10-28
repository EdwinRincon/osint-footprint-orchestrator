from pathlib import Path

import pytest

from osint_tool.accounts import load_account_index
from osint_tool.config import Settings, load_settings
from osint_tool.correlator import correlate
from osint_tool.models import Finding, Target
from osint_tool.pivots import BUILTIN_ACCOUNT_HOSTS, build_account_index, canonical_account

WMN_PATH = Path(__file__).resolve().parents[1] / "data" / "wmn-data.json"


def _settings(wmn_file: Path) -> Settings:
    return Settings(**{**load_settings().__dict__, "wmn_file": wmn_file})


def _gh(*pivots: dict[str, object]) -> Finding:
    return Finding(
        entity_type="public_profile",
        type="github_profile",
        value="https://github.com/ana",
        source="GitHub",
        confidence=1.0,
        raw={"pivots": list(pivots)},
    )


def _profile(url: str) -> Finding:
    return Finding(entity_type="x", type="profile", value=url, source="WhatsMyName", confidence=0.5)


def test_sin_dataset_el_indice_es_none(tmp_path: Path) -> None:
    assert load_account_index(_settings(tmp_path / "no-existe.json")) is None


def test_dataset_corrupto_el_indice_es_none(tmp_path: Path) -> None:
    corrupto = tmp_path / "wmn.json"
    corrupto.write_text("{no es json", encoding="utf-8")
    assert load_account_index(_settings(corrupto)) is None


def test_sin_dataset_siguen_funcionando_los_alias_integrados() -> None:
    assert canonical_account("https://x.com/Ana", index=None) == "twitter:ana"
    assert canonical_account("https://reddit.com/user/ana", index=None) is None


def test_con_el_dataset_real_se_reconoce_reddit_y_los_alias_integrados() -> None:
    index = load_account_index(_settings(WMN_PATH))
    assert index is not None
    assert canonical_account("https://www.reddit.com/user/Ana", index=index) == "reddit:ana"
    assert canonical_account("https://x.com/Ana", index=index) == "twitter:ana"
    assert canonical_account("https://github.com/Ana", index=index) == "github:ana"


def test_los_alias_integrados_ganan_al_dataset() -> None:
    index = build_account_index([("Otra", "https://x.com/{username}")])
    assert index["x.com"][()] == BUILTIN_ACCOUNT_HOSTS["x.com"][()]


def test_host_con_varias_plantillas_se_resuelve_por_prefijo() -> None:
    index = build_account_index(
        [("Foo", "https://foo.com/{username}"), ("Foo Pro", "https://foo.com/pro/{username}")]
    )
    assert canonical_account("https://foo.com/pro/ana", index=index) == "foo-pro:ana"
    assert canonical_account("https://foo.com/ana", index=index) == "foo:ana"
    assert canonical_account("https://foo.com/pro", index=index) == "foo:pro"


def test_si_dos_plantillas_comparten_prefijo_gana_la_primera() -> None:
    index = build_account_index(
        [("Primera", "https://foo.com/{username}"), ("Segunda", "https://foo.com/{username}")]
    )
    assert canonical_account("https://foo.com/ana", index=index) == "primera:ana"


@pytest.mark.parametrize("con_indice", [True, False])
def test_correlate_une_reddit_solo_con_el_indice(con_indice: bool) -> None:
    index = load_account_index(_settings(WMN_PATH)) if con_indice else None
    findings = [
        _gh({"kind": "account", "value": "reddit:ana", "explicit": True}),
        _profile("https://www.reddit.com/user/Ana"),
    ]
    relations = correlate(Target(username="ana"), findings, index)
    puente = ("profile:https://www.reddit.com/user/Ana", "account:reddit:ana")
    assert (puente in {(r.source, r.target) for r in relations}) is con_indice
