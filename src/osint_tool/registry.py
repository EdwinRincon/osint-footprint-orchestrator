"""Contrato de los módulos y registro de fuentes.

Un módulo nuevo solo necesita el decorador `@register`: no hay que editar
ninguna lista central (principio abierto/cerrado).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import fields
from typing import Protocol, TypeVar, runtime_checkable

from osint_tool.models import Finding, ModuleOutput, Target

# Entradas válidas = campos de Target (única fuente de verdad).
VALID_INPUTS: frozenset[str] = frozenset(f.name for f in fields(Target))


class UnknownModuleError(ValueError):
    """Se pidió un módulo que no está registrado."""

class ModuleSkipped(Exception):
    """El módulo no se puede ejecutar ahora (límite de uso, herramienta ausente...).

    No es un error: el informe lo mostrará como `skipped`, con este mensaje.
    """

class Module(Protocol):
    """Lo que debe cumplir cualquier fuente de información."""

    name: str
    accepts: frozenset[str]

    # El protocolo fija la frontera común sin acoplar el servicio a implementaciones concretas.
    def run(self, target: Target) -> list[Finding] | ModuleOutput:
        """Consulta la fuente y devuelve hallazgos, opcionalmente con cobertura por fuente."""
        ...


@runtime_checkable
class ProgressAwareModule(Protocol):
    """Optional protocol for modules that can report progress while running."""

    # Mantener el progreso como capacidad opcional evita imponerlo a todos los módulos.
    def set_progress_callback(
        self, callback: Callable[[int, int], None] | None
    ) -> None: ...


M = TypeVar("M", bound=Module)

_REGISTRY: dict[str, type[Module]] = {}


# Validar al registrar falla pronto, antes de que una configuración inválida llegue al usuario.
def register(cls: type[M]) -> type[M]:
    """Decorador que añade una clase de módulo al registro."""
    if not cls.name:
        raise ValueError(f"{cls.__name__}: `name` no puede estar vacío")
    unknown = cls.accepts - VALID_INPUTS
    if unknown or not cls.accepts:
        raise ValueError(
            f"{cls.name}: `accepts` debe ser un subconjunto no vacío de {sorted(VALID_INPUTS)}"
        )
    if cls.name in _REGISTRY:
        raise ValueError(f"Módulo duplicado: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


# Entregar una copia protege el registro global de mutaciones externas.
def all_modules() -> dict[str, type[Module]]:
    """Copia del registro (nombre -> clase), para `--list-modules`."""
    return dict(_REGISTRY)


# Exponer solo módulos opt-in evita activar accidentalmente consultas externas en la web.
def web_optional_modules() -> list[tuple[str, str]]:
    """Opciones activables en la web, declaradas por cada módulo."""
    return [
        (name, getattr(module, "web_label", name.replace("_", " ").title()))
        for name, module in _REGISTRY.items()
        if getattr(module, "web_opt_in", False)
    ]


# El catálogo permite que la interfaz presente capacidades declaradas junto al módulo.
def web_module_catalog() -> list[tuple[str, str, str, frozenset[str], bool]]:
    """Presentación de fuentes web y datos de entrada que las habilitan."""
    return [
        (
            name,
            getattr(module, "web_label", name.replace("_", " ").title()),
            getattr(module, "web_description", ""),
            module.accepts,
            getattr(module, "web_opt_in", False),
        )
        for name, module in _REGISTRY.items()
    ]


# Filtrar por entradas disponibles evita consultar fuentes que no pueden aportar resultados.
def applicable_modules(target: Target, names: Iterable[str] | None = None) -> list[Module]:
    """Instancias de los módulos que aceptan algún dato del `Target`.

    Args:
        target: datos de entrada ya validados.
        names: si se indica, limita la selección a estos módulos.

    Raises:
        UnknownModuleError: si algún nombre de `names` no está registrado.
    """
    selected = list(_REGISTRY) if names is None else list(names)
    unknown = [n for n in selected if n not in _REGISTRY]
    if unknown:
        raise UnknownModuleError(
            f"Módulos desconocidos: {', '.join(unknown)}. Disponibles: {', '.join(_REGISTRY)}"
        )
    provided = target.provided()
    return [_REGISTRY[n]() for n in selected if _REGISTRY[n].accepts & provided]