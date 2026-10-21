"""Correlador: convierte los hallazgos de los módulos en relaciones entre entidades.

Las relaciones son hipótesis con una confianza (0-1), no hechos probados.
La puntuación conserva el apoyo más fuerte y no presupone independencia entre fuentes.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from osint_tool.models import Finding, Relation, Target

INPUT_SOURCE = "input"  # relaciones deducidas de los datos aportados, no de una fuente
TEXT_MATCH_CONFIDENCE = 1.0  # la coincidencia textual es un hecho; que haya titularidad, no


def node_id(kind: str, value: str) -> str:
    """Identificador estable de una entidad en el grafo, p. ej. 'email:ana@ejemplo.com'."""
    return f"{kind}:{value}"


@dataclass(frozen=True)
class Rule:
    """Cómo se enlaza un tipo de hallazgo con el Target."""

    subject: str  # campo del Target del que parte la relación
    kind: str  # tipo de nodo que representa el valor del hallazgo
    label: str  # etiqueta de la relación; admite {source}


# Tipo de hallazgo -> regla. Los tipos que no estén aquí no entran en el grafo
# (siguen apareciendo en el informe).
RULES: dict[str, Rule] = {
    "breach": Rule("email", "breach", "aparece en brecha"),
    "profile": Rule("username", "profile", "perfil en {source}"),
    "dns_record": Rule("domain", "dns", "registro DNS"),
    "subdomain": Rule("domain", "domain", "subdominio"),
    "ip_address": Rule("domain", "ip", "IP"),
    "harvested_email": Rule("domain", "email", "email encontrado"),
    "whois_contact": Rule("domain", "email", "contacto WHOIS"),
    "whois_registrar": Rule("domain", "registrar", "registrador"),
    "whois_org": Rule("domain", "org", "organización"),
    "phone_region": Rule("phone", "region", "región"),
    "phone_line_type": Rule("phone", "line_type", "tipo de línea"),
    "phone_carrier": Rule("phone", "carrier", "operador"),
}


@dataclass
class _Edge:
    """Acumula las etiquetas y la confianza de cada fuente para una misma relación."""

    labels: set[str] = field(default_factory=set)
    by_source: dict[str, float] = field(default_factory=dict)

    def add(self, label: str, source: str, confidence: float) -> None:
        self.labels.add(label)
        # Varios hallazgos de la misma fuente no suman: cuenta el mejor.
        self.by_source[source] = max(self.by_source.get(source, 0.0), confidence)

    def confidence(self) -> float:
        """Apoyo más fuerte entre las fuentes, sin suponer que sean independientes."""
        return max(self.by_source.values(), default=0.0)


_Edges = dict[tuple[str, str], _Edge]


def _add_edge(
    edges: _Edges, src: str, dst: str, label: str, source: str, confidence: float
) -> None:
    edges.setdefault((src, dst), _Edge()).add(label, source, confidence)


def _link_email_to_domain(fields: dict[str, str], edges: _Edges) -> None:
    """Une el email con el dominio indicado si coinciden textualmente.

    Los datos aportados juntos no se conectan entre sí: esta coincidencia no prueba
    identidad ni titularidad, solo que el texto del email termina en ese dominio.
    """
    email, domain = fields.get("email"), fields.get("domain")
    if email and domain and email.rpartition("@")[2] == domain:
        _add_edge(
            edges,
            node_id("email", email),
            node_id("domain", domain),
            "el email termina en el dominio indicado",
            INPUT_SOURCE,
            TEXT_MATCH_CONFIDENCE,
        )


def _link_findings(fields: dict[str, str], findings: Iterable[Finding], edges: _Edges) -> None:
    """Enlaza cada hallazgo con la entidad del Target de la que proviene.

    Así, un mismo username en varias redes queda unido al mismo nodo.
    """
    for finding in findings:
        rule = RULES.get(finding.type)
        if rule is None or rule.subject not in fields:
            continue
        _add_edge(
            edges,
            node_id(rule.subject, fields[rule.subject]),
            node_id(rule.kind, finding.value),
            rule.label.format(source=finding.source),
            finding.source,
            finding.confidence,
        )


def correlate(target: Target, findings: Iterable[Finding]) -> list[Relation]:
    """Genera las relaciones entre las entidades del Target y los hallazgos."""
    fields = target.to_dict()  # campo -> valor, solo los informados
    edges: _Edges = {}
    _link_email_to_domain(fields, edges)
    _link_findings(fields, findings, edges)
    return [
        Relation(
            source=src,
            target=dst,
            label=" / ".join(sorted(edge.labels)),
            confidence=edge.confidence(),
        )
        for (src, dst), edge in sorted(edges.items())
    ]