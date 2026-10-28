import pytest

from osint_tool.config import (
    DEFAULT_BREACHES_ANALYTICS_URL,
    DEFAULT_BREACHES_API_URL,
    DEFAULT_BREACHES_REFERENCE_URL,
    DEFAULT_WMN_FILE,
    DEFAULT_WMN_UPDATE_URL,
    ConfigError,
    load_settings,
    parse_sources,
)

VARS = (
    "OSINT_HTTP_TIMEOUT",
    "OSINT_HTTP_RETRIES",
    "OSINT_CLI_TIMEOUT",
    "OSINT_OUTPUT_DIR",
    "OSINT_HARVESTER_SOURCES",
    "OSINT_WMN_FILE",
    "OSINT_WMN_UPDATE_URL",
    "OSINT_BREACHES_API_URL",
    "OSINT_BREACHES_ANALYTICS_URL",
    "OSINT_BREACHES_REFERENCE_URL",
)
EMAIL_TEMPLATE_VARS = ["OSINT_BREACHES_API_URL", "OSINT_BREACHES_ANALYTICS_URL"]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cada test parte de un entorno sin variables OSINT_*."""
    for var in VARS:
        monkeypatch.delenv(var, raising=False)


def test_valores_por_defecto() -> None:
    settings = load_settings()
    assert settings.harvester_sources == "crtsh,certspotter,hackertarget"
    assert settings.wmn_file == DEFAULT_WMN_FILE
    assert settings.wmn_update_url == DEFAULT_WMN_UPDATE_URL
    assert settings.breaches_api_url == DEFAULT_BREACHES_API_URL
    assert settings.breaches_analytics_url == DEFAULT_BREACHES_ANALYTICS_URL
    assert settings.breaches_reference_url == DEFAULT_BREACHES_REFERENCE_URL


def test_el_dataset_por_defecto_esta_en_la_carpeta_data() -> None:
    assert DEFAULT_WMN_FILE.name == "wmn-data.json"
    assert DEFAULT_WMN_FILE.parent.name == "data"


def test_fuentes_personalizadas_se_normalizan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_HARVESTER_SOURCES", " crtsh, urlscan ,")
    assert load_settings().harvester_sources == "crtsh,urlscan"


@pytest.mark.parametrize("value", ["crtsh;rm -rf", "--help", "crtsh urlscan"])
def test_fuentes_invalidas(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("OSINT_HARVESTER_SOURCES", value)
    with pytest.raises(ConfigError):
        load_settings()


def test_parse_sources_normaliza_y_rechaza_listas_vacias() -> None:
    assert parse_sources(" crtsh, certspotter ,") == "crtsh,certspotter"
    with pytest.raises(ConfigError, match="vacía"):
        parse_sources(" , ")


def test_ruta_del_dataset_se_puede_cambiar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_WMN_FILE", "mis-datos/wmn.json")
    assert str(load_settings().wmn_file).replace("\\", "/") == "mis-datos/wmn.json"


def test_ruta_vacia_equivale_al_valor_por_defecto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_WMN_FILE", "   ")
    assert load_settings().wmn_file == DEFAULT_WMN_FILE


def test_urls_personalizadas_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_WMN_UPDATE_URL", "https://espejo.test/wmn.json")
    monkeypatch.setenv("OSINT_BREACHES_API_URL", "https://api.test/check/{email}")
    monkeypatch.setenv("OSINT_BREACHES_ANALYTICS_URL", "https://api.test/analytics?e={email}")
    monkeypatch.setenv("OSINT_BREACHES_REFERENCE_URL", "https://doc.test")
    settings = load_settings()
    assert settings.wmn_update_url == "https://espejo.test/wmn.json"
    assert settings.breaches_api_url == "https://api.test/check/{email}"
    assert settings.breaches_analytics_url == "https://api.test/analytics?e={email}"
    assert settings.breaches_reference_url == "https://doc.test"


@pytest.mark.parametrize(
    "variable",
    [
        "OSINT_WMN_UPDATE_URL",
        "OSINT_BREACHES_API_URL",
        "OSINT_BREACHES_ANALYTICS_URL",
        "OSINT_BREACHES_REFERENCE_URL",
    ],
)
@pytest.mark.parametrize("value", ["http://inseguro.test/{email}", "file:///etc/passwd"])
def test_urls_que_no_son_https_se_rechazan(
    monkeypatch: pytest.MonkeyPatch, variable: str, value: str
) -> None:
    monkeypatch.setenv(variable, value)
    with pytest.raises(ConfigError, match="https://"):
        load_settings()


@pytest.mark.parametrize("variable", EMAIL_TEMPLATE_VARS)
def test_las_urls_de_brechas_deben_incluir_el_email(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    monkeypatch.setenv(variable, "https://api.test/check")
    with pytest.raises(ConfigError, match="email"):
        load_settings()


def test_numero_invalido_o_bajo_el_minimo_falla(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_HTTP_TIMEOUT", "abc")
    with pytest.raises(ConfigError, match="número"):
        load_settings()
    monkeypatch.setenv("OSINT_HTTP_TIMEOUT", "0.1")
    with pytest.raises(ConfigError, match=">="):
        load_settings()


def test_numeros_validos_se_leen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_HTTP_TIMEOUT", "3.5")
    monkeypatch.setenv("OSINT_HTTP_RETRIES", "0")
    monkeypatch.setenv("OSINT_CLI_TIMEOUT", "120")
    settings = load_settings()
    assert (settings.http_timeout, settings.http_retries, settings.cli_timeout) == (3.5, 0, 120)