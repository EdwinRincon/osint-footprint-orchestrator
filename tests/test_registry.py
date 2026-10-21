import pytest

from osint_tool import registry
from osint_tool.models import Finding, Target
from osint_tool.registry import (
    UnknownModuleError,
    applicable_modules,
    register,
    web_optional_modules,
)


class _Base:
    def run(self, target: Target) -> list[Finding]:
        return []


def _fake(name: str, accepts: set[str]) -> type[_Base]:
    return type(f"Fake_{name}", (_Base,), {"name": name, "accepts": frozenset(accepts)})


@pytest.fixture(autouse=True)
def registro_limpio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_REGISTRY", {})


def test_filtra_por_accepts() -> None:
    register(_fake("a", {"email"}))
    register(_fake("b", {"domain"}))
    mods = applicable_modules(Target(email="x@ejemplo.com"))
    assert [m.name for m in mods] == ["a"]


def test_seleccion_por_nombre() -> None:
    register(_fake("a", {"email"}))
    register(_fake("b", {"email"}))
    mods = applicable_modules(Target(email="x@ejemplo.com"), names=["b"])
    assert [m.name for m in mods] == ["b"]


def test_nombre_desconocido() -> None:
    with pytest.raises(UnknownModuleError):
        applicable_modules(Target(domain="ejemplo.com"), names=["nope"])


def test_duplicado() -> None:
    register(_fake("a", {"email"}))
    with pytest.raises(ValueError):
        register(_fake("a", {"email"}))


def test_accepts_invalido() -> None:
    with pytest.raises(ValueError):
        register(_fake("a", {"telefono"}))


def test_nombre_vacio() -> None:
    with pytest.raises(ValueError):
        register(_fake("", {"email"}))


def test_modulos_web_opcionales_se_declaran_en_el_modulo() -> None:
    module = _fake("external_tool", {"domain"})
    module.web_opt_in = True
    module.web_label = "External Tool"
    register(module)

    assert web_optional_modules() == [("external_tool", "External Tool")]