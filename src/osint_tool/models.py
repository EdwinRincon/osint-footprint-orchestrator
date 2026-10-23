"""Modelos de datos compartidos por todo el proyecto.

Este módulo no importa nada del resto del paquete: es la base del contrato
entre módulos, correlador, informes e interfaces.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    """Fecha y hora actual en UTC (con zona horaria)."""
    return datetime.now(timezone.utc)


def _to_jsonable(value: Any) -> Any:
    """Convierte recursivamente datetime, Enum y colecciones a tipos serializables en JSON."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_jsonable(v) for v in value]
    return value


@dataclass(frozen=True)
class Target:
    """Datos de entrada de la investigación.

    Todos los campos son opcionales, pero debe haber al menos uno.
    La validación de formato vive en `validation.py`, que es quien
    construye este objeto; aquí solo se garantiza que no esté vacío.
    """

    email: str | None = None
    username: str | None = None
    domain: str | None = None
    phone: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if not self.provided():
            raise ValueError("Se necesita al menos un dato de entrada.")

    def provided(self) -> frozenset[str]:
        """Nombres de los campos que tienen valor (p. ej. {'email', 'domain'})."""
        return frozenset(k for k, v in asdict(self).items() if v)

    def to_dict(self) -> dict[str, str]:
        """Solo los campos informados, útil para el informe."""
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(frozen=True)
class Finding:
    """Un hallazgo concreto devuelto por un módulo.

    Attributes:
        entity_type: Tipo de entidad a la que pertenece (email, username, domain...).
        type: Categoría del hallazgo (breach, profile, dns_record...).
        value: Valor encontrado.
        source: Nombre de la fuente (XposedOrNot, GitHub, WHOIS...).
        source_url: Referencia web de la fuente, si está disponible.
        confidence: Puntuación heurística de 0.0 a 1.0, no una probabilidad calibrada.
        raw: Dato original de la fuente, opcional.
        retrieved_at: Fecha UTC de obtención (automática).
        detail: Resumen legible del hallazgo para el informe, si la fuente lo aporta.
    """

    entity_type: str
    type: str
    value: str
    source: str
    confidence: float = 1.0
    # Un dict no es hashable: se excluye para que `Finding` sirva en sets y claves de dict.
    raw: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    retrieved_at: datetime = field(default_factory=_utcnow, compare=False)
    source_url: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence debe estar entre 0.0 y 1.0")


class Status(str, Enum):
    """Estado de ejecución de un módulo."""

    OK = "ok"
    SKIPPED = "skipped"  # límite de uso, herramienta ausente o dataset no disponible
    ERROR = "error"  # fallo al consultar o procesar la fuente


class SourceCheckStatus(str, Enum):
    """Resultado de una comprobación individual en una fuente."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass(frozen=True)
class SourceCheck:
    """Resultado auditable de comprobar una fuente, sin duplicar datos de entrada."""

    source: str
    status: SourceCheckStatus
    detail: str | None = None
    retrieved_at: datetime = field(default_factory=_utcnow)


@dataclass
class ModuleOutput:
    """Hallazgos y cobertura opcional producidos por un módulo."""

    findings: list[Finding] = field(default_factory=list)
    source_checks: list[SourceCheck] = field(default_factory=list)


@dataclass
class ModuleResult:
    """Resultado de ejecutar un módulo, con su estado y duración."""

    name: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0  # segundos
    source_checks: list[SourceCheck] = field(default_factory=list)


@dataclass(frozen=True)
class Relation:
    """Relación entre dos entidades, producida por el correlador.

    Es una hipótesis: `confidence` indica cuánto fiarse de ella.
    """

    source: str
    target: str
    label: str
    confidence: float = 0.5
    evidence: tuple[str, ...] = ()


@dataclass
class Report:
    """Resultado completo de una investigación."""

    target: Target
    results: list[ModuleResult] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utcnow)
    notes: list[str] = field(default_factory=list)  # avisos para el lector del informe
    coverage_summary: dict[str, int] = field(default_factory=dict)
    filter_summary: dict[str, str] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        """Todos los hallazgos de todos los módulos, en una sola lista."""
        return [f for r in self.results for f in r.findings]

    def to_dict(self) -> dict[str, Any]:
        """Representación serializable (los datetime se convierten a ISO 8601)."""
        data: dict[str, Any] = {
            "target": self.target.to_dict(),
            "created_at": self.created_at,
            "results": [asdict(r) for r in self.results],
            "relations": [asdict(r) for r in self.relations],
            "notes": self.notes,
        }
        if self.coverage_summary:
            data["coverage_summary"] = self.coverage_summary
        if self.filter_summary:
            data["filter_summary"] = self.filter_summary
        return {key: _to_jsonable(value) for key, value in data.items()}