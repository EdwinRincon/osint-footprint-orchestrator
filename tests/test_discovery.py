import osint_tool.modules  # noqa: F401  (el import dispara el autodescubrimiento)
from osint_tool.registry import all_modules


def test_domain_se_registra_solo() -> None:
    assert "domain" in all_modules()