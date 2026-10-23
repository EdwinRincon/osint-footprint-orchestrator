"""Interfaz web local. Solo escucha en 127.0.0.1 y no tiene autenticación."""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask.typing import ResponseReturnValue

from osint_tool.config import load_settings
from osint_tool.correlator import correlate
from osint_tool.models import (
    Finding,
    ModuleResult,
    Report,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import (
    Module,
    all_modules,
    applicable_modules,
    web_module_catalog,
    web_optional_modules,
)
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.validation import ValidationError, build_target

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 5000
MAX_FORM_BYTES = 16 * 1024  # el formulario es pequeño
MAX_ACTIVE_JOBS = 2
MAX_STORED_JOBS = 20
JOB_TTL_SECONDS = 60 * 60

# Hosts aceptados: protege contra DNS rebinding (una web externa que apunta a tu localhost).
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Solo se sirven carpetas con el formato que genera create_report_dir y estos ficheros.
RUN_ID_RE = re.compile(r"\d{8}T\d{6}-[0-9a-f]{6}")
SERVED_FILES = {
    "report.html",
    "report.json",
    "graph.html",
    "graph.js",
    "cytoscape.min.js",
    "CYTOSCAPE-LICENSE.txt",
}

FIELDS = (
    ("email", "Email", "ana@ejemplo.com"),
    ("username", "Username", "anaperez"),
    ("domain", "Dominio", "ejemplo.com"),
    ("phone", "Teléfono (formato internacional)", "+34600000000"),
    ("name", "Nombre", "Ana Pérez"),
)

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; frame-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'self'; base-uri 'none'"
)


@dataclass
class InvestigationJob:
    job_id: str
    target: Target
    modules: list[Module]
    created_at: float = field(default_factory=time.monotonic)
    status: str = "queued"
    completed_modules: int = 0
    total_modules: int = 0
    current_module: str | None = None
    current_completed: int = 0
    current_total: int = 0
    module_results: list[dict[str, str | int | float | None]] = field(default_factory=list)
    report: Report | None = None
    error: str | None = None


# Filtrar una copia del reporte evita mutar el resultado original que aún consultan clientes.
def _filter_report(
    report: Report, statuses: set[str], query: str, module: str
) -> Report:
    # Calcula la cobertura completa antes de filtrar para que los totales no dependan de la vista.
    source_checks = [check for result in report.results for check in result.source_checks]
    counts = Counter(check.status.value for check in source_checks)
    query = query.strip().casefold()

    # Unir campos de contexto permite buscar sin depender de un único texto visible.
    def finding_matches(result: ModuleResult, finding: Finding) -> bool:
        if not query:
            return True
        text = " ".join(
            (
                result.name,
                finding.type,
                finding.value,
                finding.source,
                finding.detail or "",
                finding.source_url or "",
            )
        ).casefold()
        return query in text

    # Vincular DNS por record_type preserva la correspondencia de fuente tras el filtrado.
    def check_matches_finding(
        result: ModuleResult, check: SourceCheck, finding: Finding
    ) -> bool:
        if check.source == finding.source:
            return True
        record_type = finding.raw.get("record_type")
        # Los hallazgos DNS comparten la fuente "DNS"; raw conserva el tipo que enlaza la consulta.
        return (
            result.name == "domain"
            and finding.source == "DNS"
            and isinstance(record_type, str)
            and check.source == f"DNS {record_type}"
        )

    # Aplicar criterios juntos mantiene coherentes la tabla de cobertura y sus hallazgos.
    def included(result: ModuleResult, check: SourceCheck) -> bool:
        if module and result.name != module:
            return False
        status = check.status.value
        text = f"{check.source} {check.detail or ''}".casefold()
        if status not in statuses:
            return False
        if not query or query in text:
            return True
        return any(
            check_matches_finding(result, check, finding)
            and finding_matches(result, finding)
            for finding in result.findings
        )

    selected_checks = [
        check for result in report.results for check in result.source_checks
        if included(result, check)
    ]
    results: list[ModuleResult] = []
    for result in report.results:
        if module and result.name != module:
            continue
        checks = [check for check in result.source_checks if included(result, check)]
        findings = [
            finding
            for finding in result.findings
            if (
                not result.source_checks
                or any(
                    check.status is SourceCheckStatus.FOUND
                    and check_matches_finding(result, check, finding)
                    and check in checks
                    for check in result.source_checks
                )
            )
            and (
                not query
                or finding_matches(result, finding)
                or any(
                    check_matches_finding(result, check, finding)
                    and included(result, check)
                    and query in f"{check.source} {check.detail or ''}".casefold()
                    for check in result.source_checks
                )
            )
        ]
        results.append(replace(result, findings=findings, source_checks=checks))

    filtered = replace(report, results=results, notes=list(report.notes))
    # Las relaciones se derivan de hallazgos; conservar las originales filtraría datos ocultos.
    filtered.relations = correlate(report.target, filtered.findings)
    filtered.filter_summary = {
        "statuses": ", ".join(sorted(statuses)) or "ninguno",
        "search": query,
    }
    if module:
        filtered.filter_summary["module"] = module
    if source_checks:
        filtered.coverage_summary = {
            "total": len(source_checks),
            "included": len(selected_checks),
            **{status.value: counts.get(status.value, 0) for status in SourceCheckStatus},
        }
        filtered.notes.append(
            "Las comprobaciones visibles están filtradas; el resumen de cobertura conserva "
            "los totales completos de la búsqueda."
        )
    return filtered


class InvestigationJobs:
    """Keeps short-lived local investigation state and executes jobs off-request."""

    # Compartir un lock evita snapshots parciales entre las peticiones y los workers.
    def __init__(self) -> None:
        # Requests leen snapshots mientras el worker actualiza progreso y resultados.
        self._jobs: dict[str, InvestigationJob] = {}
        self._lock = threading.Lock()

    # Limitar y caducar trabajos protege el proceso local de acumulación de consultas concurrentes.
    def submit(self, target: Target, modules: list[Module]) -> InvestigationJob | None:
        now = time.monotonic()
        with self._lock:
            # Monotonic evita que cambios en el reloj del sistema alteren la caducidad.
            expired = [
                job_id
                for job_id, job in self._jobs.items()
                if job.status in {"complete", "failed"}
                and now - job.created_at > JOB_TTL_SECONDS
            ]
            for job_id in expired:
                del self._jobs[job_id]
            completed_jobs = sorted(
                (
                    job
                    for job in self._jobs.values()
                    if job.status in {"complete", "failed"}
                ),
                key=lambda job: job.created_at,
            )
            while len(self._jobs) >= MAX_STORED_JOBS and completed_jobs:
                del self._jobs[completed_jobs.pop(0).job_id]
            if len(self._jobs) >= MAX_STORED_JOBS:
                return None
            # Cada investigación puede generar muchas peticiones externas.
            active_jobs = sum(
                job.status in {"queued", "running"} for job in self._jobs.values()
            )
            if active_jobs >= MAX_ACTIVE_JOBS:
                return None
            job_id = secrets.token_urlsafe(24)
            job = InvestigationJob(job_id, target, modules, total_modules=len(modules))
            self._jobs[job_id] = job

        # El worker necesita el mismo lock para actualizar estado, así que arráncalo fuera de él.
        worker = threading.Thread(
            target=self._execute,
            args=(job,),
            name=f"osint-job-{job_id[:8]}",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            with self._lock:
                del self._jobs[job_id]
            raise
        return job

    # Devolver None permite que la capa HTTP convierta IDs desconocidos en un 404 consistente.
    def get(self, job_id: str) -> InvestigationJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    # Copiar resultados bajo el lock evita exponer colecciones que el worker aún modifica.
    def snapshot(self, job: InvestigationJob) -> dict[str, object]:
        with self._lock:
            return {
                "status": job.status,
                "completed_modules": job.completed_modules,
                "total_modules": job.total_modules,
                "current_module": job.current_module,
                "current_completed": job.current_completed,
                "current_total": job.current_total,
                "modules": list(job.module_results),
                "error": job.error,
            }

    # Ocultar reportes incompletos evita que los clientes confundan progreso con resultado final.
    def completed_report(self, job: InvestigationJob) -> Report | None:
        with self._lock:
            return job.report if job.status == "complete" else None

    # Ejecutar en segundo plano evita mantener abierta la petición durante consultas externas.
    def _execute(self, job: InvestigationJob) -> None:
        with self._lock:
            job.status = "running"

        # Actualizar bajo lock mantiene cada lectura del estado internamente consistente.
        def module_progress(name: str, completed: int, total: int) -> None:
            with self._lock:
                job.current_module = name
                job.current_completed = completed
                job.current_total = total

        # Publicar cada resultado permite consultar avance antes de tener el reporte final.
        def module_finished(result: ModuleResult, completed: int, total: int) -> None:
            with self._lock:
                job.completed_modules = completed
                job.total_modules = total
                job.module_results.append(
                    {
                        "name": result.name,
                        "status": result.status.value,
                        "findings": len(result.findings),
                        "duration": result.duration,
                        "error": result.error,
                    }
                )
                job.current_module = None
                job.current_completed = 0
                job.current_total = 0

        try:
            report = run_investigation(
                job.target,
                job.modules,
                on_progress=module_finished,
                on_module_progress=module_progress,
            )
        except Exception as exc:
            logger.exception(
                "Falló la investigación en segundo plano (%s)", type(exc).__name__
            )
            with self._lock:
                job.status = "failed"
                # La excepción completa queda en el registro local, no en la respuesta web.
                job.error = "No se pudo completar la investigación. Consulta el registro local."
            return

        with self._lock:
            job.report = report
            job.status = "complete"


# Una factory aislada permite configurar almacenamiento y clientes de prueba sin estado global.
def create_app(output_dir: Path | None = None) -> Flask:
    """Crea la aplicación. `output_dir` permite usar otra carpeta (p. ej. en tests)."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FORM_BYTES
    # Ruta absoluta: send_from_directory interpreta las relativas desde la app, no desde el cwd.
    out_dir = (output_dir or load_settings().output_dir).resolve()
    jobs = InvestigationJobs()
    app.extensions["osint_jobs"] = jobs

    # Centralizar el 404 evita que cada ruta interprete IDs inexistentes de forma distinta.
    def get_job(job_id: str) -> InvestigationJob:
        job = jobs.get(job_id)
        if job is None:
            abort(404)
        return job

    # Verificar host y origen antes de procesar formularios reduce solicitudes cross-site.
    @app.before_request
    def guard() -> None:
        hostname = urlparse(f"//{request.host}").hostname
        if hostname not in ALLOWED_HOSTS:
            abort(400)
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and urlparse(origin).netloc != request.host:
                abort(403)  # formulario enviado desde otra web (CSRF)

    # Aplicar cabeceras en un hook evita que alguna ruta omita protecciones de respuesta.
    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        # Los informes contienen datos personales: que el navegador no los guarde en caché.
        response.headers["Cache-Control"] = "no-store"
        return response

    # Reutilizar el formulario conserva valores y opciones al devolver errores de validación.
    def form(
        error: str | None = None,
        values: dict[str, str] | None = None,
        selected_modules: set[str] | None = None,
    ) -> str:
        return render_template(
            "index.html",
            fields=FIELDS,
            notice=LEGAL_NOTICE,
            error=error,
            values=values or {},
            module_catalog=web_module_catalog(),
            selected_modules=selected_modules or set(),
        )

    # Compartir una ruta GET separa la presentación inicial de la tramitación de búsquedas.
    @app.get("/")
    def index() -> ResponseReturnValue:
        return form()

    # Validar módulos y objetivo antes de encolar protege el worker de entradas no confiables.
    @app.post("/")
    def search() -> ResponseReturnValue:
        values = {name: request.form.get(name, "") for name, _, _ in FIELDS}
        optional_modules = dict(web_optional_modules())
        selected_modules = set(request.form.getlist("modules"))
        invalid_modules = selected_modules - optional_modules.keys()
        if invalid_modules:
            return (
                form(
                    error="La selección de herramientas opcionales no es válida.",
                    values=values,
                    selected_modules=selected_modules & optional_modules.keys(),
                ),
                400,
            )
        try:
            target = build_target(**values)
        except ValidationError as exc:
            return (
                form(error=str(exc), values=values, selected_modules=selected_modules),
                400,
            )

        module_names = [
            name
            for name in all_modules()
            if name not in optional_modules or name in selected_modules
        ]
        modules = applicable_modules(target, module_names)
        job = jobs.submit(target, modules)
        if job is None:
            return (
                form(
                    error=(
                        "Ya hay búsquedas en curso. Espera a que termine una antes "
                        "de iniciar otra."
                    ),
                    values=values,
                    selected_modules=selected_modules,
                ),
                429,
            )
        return redirect(url_for("job_results", job_id=job.job_id), code=303)

    # La página consulta estado aparte para que investigaciones largas no bloqueen una respuesta.
    @app.get("/jobs/<job_id>")
    def job_results(job_id: str) -> ResponseReturnValue:
        get_job(job_id)
        return render_template(
            "results.html",
            job_id=job_id,
            status_url=url_for("job_status", job_id=job_id),
            data_url=url_for("job_data", job_id=job_id),
            report_url=url_for("generate_report", job_id=job_id),
        )

    # Exponer un snapshot pequeño permite actualizar progreso sin serializar hallazgos cada vez.
    @app.get("/jobs/<job_id>/status")
    def job_status(job_id: str) -> ResponseReturnValue:
        job = get_job(job_id)
        return jsonify(jobs.snapshot(job))

    # Separar datos completos del estado limita la transferencia durante el sondeo frecuente.
    @app.get("/jobs/<job_id>/data")
    def job_data(job_id: str) -> ResponseReturnValue:
        job = get_job(job_id)
        report = jobs.completed_report(job)
        if report is None:
            abort(409)
        return jsonify(
            {
                "modules": [
                    {
                        "name": result.name,
                        "status": result.status.value,
                        "findings": len(result.findings),
                        "duration": result.duration,
                        "error": result.error,
                    }
                    for result in report.results
                ],
                "source_checks": [
                    {
                        "module": result.name,
                        "source": check.source,
                        "status": check.status.value,
                        "detail": check.detail or "",
                        "profile_url": next(
                            (
                                finding.source_url
                                for finding in result.findings
                                if finding.source == check.source
                            ),
                            None,
                        ),
                    }
                    for result in report.results
                    for check in result.source_checks
                ],
                "findings": len(report.findings),
                "finding_items": [
                    {
                        "module": result.name,
                        "type": finding.type,
                        "value": finding.value,
                        "source": finding.source,
                        "record_type": str(finding.raw.get("record_type") or ""),
                        "detail": finding.detail or "",
                        "confidence": finding.confidence,
                        "source_url": finding.source_url,
                    }
                    for result in report.results
                    for finding in result.findings
                ],
                "relations": len(report.relations),
                "relation_items": [
                    {
                        "source": relation.source,
                        "target": relation.target,
                        "label": relation.label,
                        "evidence": list(relation.evidence),
                        "confidence": relation.confidence,
                    }
                    for relation in report.relations
                ],
            }
        )

    # Generar una copia filtrada conserva intacto el resultado original para otras vistas.
    @app.post("/jobs/<job_id>/report")
    def generate_report(job_id: str) -> ResponseReturnValue:
        job = get_job(job_id)
        report = jobs.completed_report(job)
        if report is None:
            abort(409)

        valid_statuses = {status.value for status in SourceCheckStatus}
        selected_statuses = set(request.form.getlist("statuses"))
        if selected_statuses - valid_statuses:
            abort(400)
        query = request.form.get("query", "")[:100]
        module = request.form.get("module", "").strip()
        if module and module not in {result.name for result in report.results}:
            abort(400)
        filtered_report = _filter_report(report, selected_statuses, query, module)
        try:
            directory, paths = write_reports(filtered_report, out_dir, "all")
        except OSError:
            logger.exception("No se pudo escribir el informe filtrado")
            return jsonify({"error": "No se pudo escribir el informe."}), 500
        return jsonify(
            {
                "report_url": url_for(
                    "serve_report", run_id=directory.name, filename="report.html"
                ),
                "download_urls": {
                    filename: url_for(
                        "serve_report", run_id=directory.name, filename=filename
                    )
                    for filename in ("report.html", "report.json")
                },
                "graph_url": (
                    url_for(
                        "serve_report", run_id=directory.name, filename="graph.html"
                    )
                    if (directory / "graph.html").is_file()
                    else None
                ),
                "files": [path.name for path in paths],
            }
        )

    # Restringir IDs y nombres permite servir solo artefactos generados, no rutas arbitrarias.
    @app.get("/reports/<run_id>/<filename>")
    def serve_report(run_id: str, filename: str) -> ResponseReturnValue:
        if not RUN_ID_RE.fullmatch(run_id) or filename not in SERVED_FILES:
            abort(404)
        return send_from_directory(out_dir / run_id, filename)

    return app


# Mantener el servidor limitado a localhost evita publicar investigaciones en interfaces externas.
def main() -> None:
    create_app().run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()