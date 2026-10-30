"""Bounded, local-only investigation sessions with explicit, provenance-bearing pivots."""

from __future__ import annotations

import json
import re
import shutil
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from osint_tool.config import MAX_SESSION_DEPTH, MAX_SESSION_TARGETS
from osint_tool.models import Finding, ModuleResult, Relation, Report, SourceCheck, Target
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.validation import ValidationError, build_target

SESSION_SCHEMA_VERSION = 1
PIVOT_FIELDS = ("email", "username", "domain", "phone", "name")
EDGE_LABEL = "unverified hypothesis"
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b((?:OSINT_[A-Z0-9_]*(?:KEY|TOKEN)|api[_-]?key|access[_-]?token|authorization))"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_SESSION_ID_RE = re.compile(r"[0-9a-f]{32}")
_KNOWN_ENTRY_STATUSES = frozenset({"running", "completed", "failed", "interrupted"})


class SessionError(ValueError):
    """A session operation violates a configured bound or invariant."""


class EntryStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class SessionEntry:
    entry_id: str
    target: Target
    depth: int
    status: EntryStatus
    parent_entry_id: str | None = None
    report: Report | None = field(default=None, repr=False)
    report_directory: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class SessionEdge:
    parent_entry_id: str
    child_entry_id: str
    source_module: str
    source_url: str | None
    evidence_text: str
    confidence: float
    label: str = EDGE_LABEL


@dataclass(frozen=True)
class SavedSession:
    session_id: str
    directory: Path
    created_at: str
    node_count: int
    status: str
    safe_to_delete: bool


@dataclass(frozen=True)
class PivotChoice:
    parent_entry_id: str
    target_type: str
    target: Target
    finding: Finding
    source_module: str


def _target_for_field(field_name: str, value: str) -> Target:
    if field_name == "email":
        return build_target(email=value)
    if field_name == "username":
        return build_target(username=value)
    if field_name == "domain":
        return build_target(domain=value)
    if field_name == "phone":
        return build_target(phone=value)
    if field_name == "name":
        return build_target(name=value)
    raise SessionError(f"Tipo de pivote no admitido: {field_name}")


def _validated_target(target: Target) -> Target:
    return build_target(
        email=target.email,
        username=target.username,
        domain=target.domain,
        phone=target.phone,
        name=target.name,
    )


def _canonical_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).split()).casefold()


def target_identifiers(target: Target) -> frozenset[tuple[str, str]]:
    """Canonical identity pairs used to prevent repeated target runs."""
    return frozenset((kind, _canonical_text(value)) for kind, value in target.to_dict().items())


def _clean_source_url(value: str | None, api_key: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not host
            or parts.username
            or parts.password
            or host.lower().startswith("api.")
            or parts.path.lower().endswith(".php")
        ):
            return None
        netloc = host
        if parts.port is not None:
            netloc = f"{host}:{parts.port}"
        clean = urlunsplit((parts.scheme.lower(), netloc, parts.path, "", ""))
    except ValueError:
        return None
    return _redact_secrets(clean, api_key)


def safe_source_url(value: str | None, api_key: str | None = None) -> str | None:
    """Return a source reference without credentials, query parameters, or API request hosts."""
    return _clean_source_url(value, api_key)


def safe_evidence_text(value: str | None, api_key: str | None = None) -> str:
    """Redact secrets and URLs from free-form evidence text."""
    return _safe_text(value, api_key) or ""


def _redact_secrets(value: str, api_key: str | None) -> str:
    if api_key:
        value = value.replace(api_key, "[REDACTED]")
    value = _SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", value)
    return _BEARER_RE.sub("Bearer [token removed]", value)


def _safe_text(value: str | None, api_key: str | None) -> str | None:
    if value is None:
        return None
    text = _redact_secrets(value, api_key)
    return _URL_RE.sub("[URL omitted]", text)


def _safe_value(value: str, api_key: str | None) -> str:
    text = _redact_secrets(value, api_key)
    if text.lower().startswith(("http://", "https://")):
        return _clean_source_url(text, api_key) or "[URL omitted]"
    return text


def _safe_target(target: Target, api_key: str | None) -> dict[str, str]:
    return {
        kind: _safe_value(value, api_key)
        for kind, value in target.to_dict().items()
    }


def _safe_finding(finding: Finding, api_key: str | None) -> dict[str, object]:
    return {
        "entity_type": finding.entity_type,
        "type": finding.type,
        "value": _safe_value(finding.value, api_key),
        "source": _safe_text(finding.source, api_key),
        "source_url": _clean_source_url(finding.source_url, api_key),
        "confidence": finding.confidence,
        "detail": _safe_text(finding.detail, api_key),
    }


def safe_report(report: Report, api_key: str | None = None) -> Report:
    """Copy a report into a safe allowlisted form before writing it within a session."""
    target = Target(
        **{
            key: _safe_value(value, api_key)
            for key, value in report.target.to_dict().items()
        }
    )
    results = [
        ModuleResult(
            name=result.name,
            status=result.status,
            findings=[
                Finding(
                    entity_type=finding.entity_type,
                    type=finding.type,
                    value=_safe_value(finding.value, api_key),
                    source=_safe_text(finding.source, api_key) or "",
                    confidence=finding.confidence,
                    source_url=_clean_source_url(finding.source_url, api_key),
                    detail=_safe_text(finding.detail, api_key),
                )
                for finding in result.findings
            ],
            error=_safe_text(result.error, api_key),
            duration=result.duration,
            source_checks=[
                SourceCheck(
                    source=_safe_text(check.source, api_key) or "",
                    status=check.status,
                    detail=_safe_text(check.detail, api_key),
                    retrieved_at=check.retrieved_at,
                )
                for check in result.source_checks
            ],
        )
        for result in report.results
    ]
    relations = [
        Relation(
            source=_safe_text(relation.source, api_key) or "",
            target=_safe_text(relation.target, api_key) or "",
            label=_safe_text(relation.label, api_key) or "",
            confidence=relation.confidence,
            evidence=tuple(_safe_text(item, api_key) or "" for item in relation.evidence),
        )
        for relation in report.relations
    ]
    return Report(
        target=target,
        results=results,
        relations=relations,
        created_at=report.created_at,
        notes=[_safe_text(note, api_key) or "" for note in report.notes],
        coverage_summary=dict(report.coverage_summary),
        filter_summary={
            key: _safe_text(value, api_key) or "" for key, value in report.filter_summary.items()
        },
    )


def _report_data(report: Report, api_key: str | None) -> dict[str, object]:
    safe = safe_report(report, api_key)
    return {
        "target": safe.target.to_dict(),
        "created_at": safe.created_at.isoformat(),
        "results": [
            {
                "name": result.name,
                "status": result.status.value,
                "error": result.error,
                "findings": [_safe_finding(finding, api_key) for finding in result.findings],
                "source_checks": [
                    {"source": check.source, "status": check.status.value}
                    for check in result.source_checks
                ],
            }
            for result in safe.results
        ],
        "relations": [
            {
                "source": relation.source,
                "target": relation.target,
                "label": relation.label,
                "confidence": relation.confidence,
                "evidence": list(relation.evidence),
            }
            for relation in safe.relations
        ],
        "notes": safe.notes,
    }


def _listed_session_status(schema_version: object, nodes: list[object]) -> str:
    if type(schema_version) is not int or schema_version != SESSION_SCHEMA_VERSION:
        return "versión no compatible"
    node_statuses: list[str] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        status = node.get("status")
        if isinstance(status, str) and status in _KNOWN_ENTRY_STATUSES:
            node_statuses.append(status)
    if EntryStatus.RUNNING.value in node_statuses:
        return EntryStatus.INTERRUPTED.value
    return node_statuses[-1] if node_statuses else "unknown"


def list_saved_sessions(output_dir: Path) -> list[SavedSession]:
    """List local session folders without trusting their serialized contents."""
    root = output_dir / "sessions"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise SessionError("La carpeta local de sesiones no es segura.")

    sessions: list[SavedSession] = []
    for directory in root.iterdir():
        if not _SESSION_ID_RE.fullmatch(directory.name):
            continue
        if directory.is_symlink() or not directory.is_dir():
            sessions.append(
                SavedSession(
                    directory.name,
                    directory,
                    "desconocida",
                    0,
                    "unsafe",
                    False,
                )
            )
            continue
        try:
            data = json.loads((directory / "session.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if (
            not isinstance(data, dict)
            or data.get("session_id") != directory.name
            or not isinstance(data.get("nodes"), list)
        ):
            sessions.append(
                SavedSession(
                    directory.name,
                    directory,
                    "desconocida",
                    0,
                    "corrupt",
                    True,
                )
            )
            continue
        nodes = data["nodes"]
        created_at = data.get("created_at")
        try:
            created_at = (
                datetime.fromisoformat(created_at).isoformat()
                if isinstance(created_at, str)
                else "desconocida"
            )
        except ValueError:
            created_at = "desconocida"
        session_status = _listed_session_status(data.get("schema_version"), nodes)
        sessions.append(
            SavedSession(
                directory.name,
                directory,
                created_at,
                len(nodes),
                session_status,
                True,
            )
        )
    return sorted(sessions, key=lambda session: session.created_at, reverse=True)


def delete_saved_session(output_dir: Path, session_id: str) -> None:
    """Delete one UUID-named session directly under the configured local sessions folder."""
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise SessionError("Identificador de sesión no válido.")
    root = output_dir / "sessions"
    if root.is_symlink():
        raise SessionError("La carpeta local de sesiones no es segura.")
    session_directory = root / session_id
    if session_directory.is_symlink():
        raise SessionError("La carpeta de sesión no se puede eliminar de forma segura.")
    resolved_root = root.resolve()
    resolved_directory = session_directory.resolve()
    if resolved_directory.parent != resolved_root or resolved_directory.name != session_id:
        raise SessionError("La carpeta de sesión no se puede eliminar de forma segura.")
    if not resolved_directory.is_dir():
        raise SessionError("La sesión local no existe.")
    shutil.rmtree(resolved_directory)


@dataclass
class InvestigationSession:
    session_id: str
    output_dir: Path = field(repr=False)
    directory: Path
    max_depth: int
    max_targets: int
    api_key: str | None = field(default=None, repr=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    entries: list[SessionEntry] = field(default_factory=list)
    edges: list[SessionEdge] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        output_dir: Path,
        target: Target,
        max_depth: int = MAX_SESSION_DEPTH,
        max_targets: int = MAX_SESSION_TARGETS,
        api_key: str | None = None,
    ) -> InvestigationSession:
        if not 0 <= max_depth <= MAX_SESSION_DEPTH:
            raise SessionError(f"La profundidad máxima es {MAX_SESSION_DEPTH}.")
        if not 1 <= max_targets <= MAX_SESSION_TARGETS:
            raise SessionError(f"El total de objetivos debe estar entre 1 y {MAX_SESSION_TARGETS}.")
        normalized_target = _validated_target(target)
        session_id = uuid.uuid4().hex
        sessions_root = output_dir / "sessions"
        if sessions_root.is_symlink():
            raise SessionError("La carpeta local de sesiones no es segura.")
        directory = sessions_root / session_id
        directory.mkdir(parents=True, exist_ok=False)
        session = cls(
            session_id=session_id,
            output_dir=output_dir,
            directory=directory,
            max_depth=max_depth,
            max_targets=max_targets,
            api_key=api_key,
            entries=[
                SessionEntry(
                    entry_id="entry-1",
                    target=normalized_target,
                    depth=0,
                    status=EntryStatus.RUNNING,
                )
            ],
        )
        session.save()
        return session

    @property
    def remaining_targets(self) -> int:
        return max(0, self.max_targets - len(self.entries))

    @property
    def remaining_depth(self) -> int:
        deepest = max((entry.depth for entry in self.entries), default=0)
        return max(0, self.max_depth - deepest)

    def entry(self, entry_id: str) -> SessionEntry:
        for entry in self.entries:
            if entry.entry_id == entry_id:
                return entry
        raise SessionError("La entrada de sesión no existe.")

    def contains_target(self, target: Target) -> bool:
        identifiers = target_identifiers(target)
        return any(identifiers & target_identifiers(entry.target) for entry in self.entries)

    def can_pivot_from(self, entry_id: str) -> bool:
        try:
            parent = self.entry(entry_id)
        except SessionError:
            return False
        return (
            parent.status is EntryStatus.COMPLETED
            and parent.depth < self.max_depth
            and self.remaining_targets > 0
        )

    def pivot_choices(self) -> list[PivotChoice]:
        choices: list[PivotChoice] = []
        if self.remaining_targets <= 0:
            return choices
        for parent in self.entries:
            if (
                parent.status is not EntryStatus.COMPLETED
                or parent.report is None
                or parent.depth >= self.max_depth
            ):
                continue
            for result in parent.report.results:
                for finding in result.findings:
                    for target_type in PIVOT_FIELDS:
                        try:
                            target = _target_for_field(target_type, finding.value)
                        except ValidationError:
                            continue
                        if self.contains_target(target):
                            continue
                        choices.append(
                            PivotChoice(
                                parent_entry_id=parent.entry_id,
                                target_type=target_type,
                                target=target,
                                finding=finding,
                                source_module=result.name,
                            )
                        )
        return choices

    def add_pivot(self, choice: PivotChoice) -> SessionEntry:
        if choice not in self.pivot_choices():
            raise SessionError("El pivote no coincide con un hallazgo validado de esta sesión.")
        if not self.can_pivot_from(choice.parent_entry_id):
            raise SessionError("Se alcanzó el límite de profundidad o de objetivos.")
        if choice.target_type not in PIVOT_FIELDS:
            raise SessionError("Tipo de pivote no admitido.")
        value = choice.target.to_dict().get(choice.target_type)
        if value is None or len(choice.target.provided()) != 1:
            raise SessionError("El pivote debe contener exactamente un tipo validado.")
        try:
            normalized_target = _target_for_field(choice.target_type, choice.finding.value)
        except ValidationError as exc:
            raise SessionError("El valor observado no pasa el validador elegido.") from exc
        if normalized_target.to_dict().get(choice.target_type) != value:
            raise SessionError("El pivote debe conservar el valor observado.")
        if self.contains_target(normalized_target):
            raise SessionError("Este objetivo ya se ejecutó en la sesión.")
        parent = self.entry(choice.parent_entry_id)
        child_id = f"entry-{len(self.entries) + 1}"
        child = SessionEntry(
            entry_id=child_id,
            target=normalized_target,
            depth=parent.depth + 1,
            status=EntryStatus.RUNNING,
            parent_entry_id=parent.entry_id,
        )
        edge = SessionEdge(
            parent_entry_id=parent.entry_id,
            child_entry_id=child_id,
            source_module=choice.source_module,
            source_url=_clean_source_url(choice.finding.source_url, self.api_key),
            evidence_text=_safe_text(
                f"{choice.finding.value}"
                + (f" — {choice.finding.detail}" if choice.finding.detail else ""),
                self.api_key,
            )
            or "",
            confidence=choice.finding.confidence,
        )
        self.entries.append(child)
        self.edges.append(edge)
        self.save()
        return child

    def complete_entry(
        self, entry_id: str, report: Report, report_directory: Path | None = None
    ) -> None:
        entry = self.entry(entry_id)
        entry.report = report
        entry.status = EntryStatus.COMPLETED
        entry.error = None
        entry.report_directory = self._relative_report_directory(report_directory)
        self.save()

    def fail_entry(
        self,
        entry_id: str,
        error_type: str,
        report: Report | None = None,
        report_directory: Path | None = None,
    ) -> None:
        entry = self.entry(entry_id)
        entry.report = report
        entry.status = EntryStatus.FAILED
        entry.error = f"Entry failed ({error_type})"
        entry.report_directory = self._relative_report_directory(report_directory)
        self.save()

    def _relative_report_directory(self, directory: Path | None) -> str | None:
        if directory is None:
            return None
        try:
            return directory.resolve().relative_to(self.directory.resolve()).as_posix()
        except ValueError as exc:
            raise SessionError("El informe debe permanecer dentro de la sesión local.") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "notice": LEGAL_NOTICE,
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "limits": {"max_depth": self.max_depth, "max_targets": self.max_targets},
            "remaining_budget": {
                "depth": self.remaining_depth,
                "targets": self.remaining_targets,
            },
            "nodes": [
                {
                    "id": entry.entry_id,
                    "parent_entry_id": entry.parent_entry_id,
                    "depth": entry.depth,
                    "status": entry.status.value,
                    "target": _safe_target(entry.target, self.api_key),
                    "error": entry.error,
                    "report_directory": entry.report_directory,
                    "report": (
                        _report_data(entry.report, self.api_key)
                        if entry.report is not None
                        else None
                    ),
                }
                for entry in self.entries
            ],
            "edges": [
                {
                    "parent_entry_id": edge.parent_entry_id,
                    "child_entry_id": edge.child_entry_id,
                    "source_module": _safe_text(edge.source_module, self.api_key),
                    "source_url": edge.source_url,
                    "evidence_text": _safe_text(edge.evidence_text, self.api_key),
                    "confidence": edge.confidence,
                    "label": EDGE_LABEL,
                }
                for edge in self.edges
            ],
        }

    def save(self) -> Path:
        if not _SESSION_ID_RE.fullmatch(self.session_id):
            raise SessionError("Identificador de sesión no válido.")
        sessions_root = self.output_dir / "sessions"
        if sessions_root.is_symlink() or self.directory.is_symlink():
            raise SessionError("La carpeta de sesión no se puede guardar de forma segura.")
        expected_parent = sessions_root.resolve()
        resolved_directory = self.directory.resolve()
        if (
            resolved_directory.parent != expected_parent
            or resolved_directory.name != self.session_id
        ):
            raise SessionError("La carpeta de sesión no es local a su raíz.")
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / "session.json"
        temporary = self.directory / f".session-{uuid.uuid4().hex}.tmp"
        content = json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(content)
            temporary.replace(path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
        return path

    def delete(self) -> None:
        delete_saved_session(self.output_dir, self.session_id)


def network_recipients(module: object) -> tuple[str, ...]:
    """Resolve declared recipients, rejecting network modules without disclosure metadata."""
    if not getattr(module, "requires_network", False):
        return ()
    recipients = getattr(module, "third_party_recipients", None)
    if callable(recipients):
        recipients = recipients()
    if not isinstance(recipients, (tuple, list)) or not recipients:
        raise SessionError("El módulo de red no declara sus destinatarios.")
    if any(not isinstance(item, str) or not item.strip() for item in recipients):
        raise SessionError("El módulo declara destinatarios no válidos.")
    return tuple(dict.fromkeys(item.strip() for item in recipients))
