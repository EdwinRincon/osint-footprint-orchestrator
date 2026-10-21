"""Interfaz web local. Solo escucha en 127.0.0.1 y no tiene autenticación."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from flask.typing import ResponseReturnValue

from osint_tool.config import load_settings
from osint_tool.registry import all_modules, applicable_modules, web_optional_modules
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.validation import ValidationError, build_target

HOST = "127.0.0.1"
PORT = 5000
MAX_FORM_BYTES = 16 * 1024  # el formulario es pequeño

# Hosts aceptados: protege contra DNS rebinding (una web externa que apunta a tu localhost).
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Solo se sirven carpetas con el formato que genera create_report_dir y estos ficheros.
RUN_ID_RE = re.compile(r"\d{8}T\d{6}-[0-9a-f]{6}")
SERVED_FILES = {"report.html", "report.json", "graph.png", "graph.dot"}

FIELDS = (
    ("email", "Email", "ana@ejemplo.com"),
    ("username", "Username", "anaperez"),
    ("domain", "Dominio", "ejemplo.com"),
    ("phone", "Teléfono (formato internacional)", "+34600000000"),
    ("name", "Nombre", "Ana Pérez"),
)

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def create_app(output_dir: Path | None = None) -> Flask:
    """Crea la aplicación. `output_dir` permite usar otra carpeta (p. ej. en tests)."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_FORM_BYTES
    # Ruta absoluta: send_from_directory interpreta las relativas desde la app, no desde el cwd.
    out_dir = (output_dir or load_settings().output_dir).resolve()

    @app.before_request
    def guard() -> None:
        hostname = urlparse(f"//{request.host}").hostname
        if hostname not in ALLOWED_HOSTS:
            abort(400)
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and urlparse(origin).netloc != request.host:
                abort(403)  # formulario enviado desde otra web (CSRF)

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        # Los informes contienen datos personales: que el navegador no los guarde en caché.
        response.headers["Cache-Control"] = "no-store"
        return response

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
            optional_modules=web_optional_modules(),
            selected_modules=selected_modules or set(),
        )

    @app.get("/")
    def index() -> ResponseReturnValue:
        return form()

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
        report = run_investigation(target, modules)
        directory, _ = write_reports(report, out_dir, "all")
        return redirect(f"/reports/{directory.name}/report.html", code=303)

    @app.get("/reports/<run_id>/<filename>")
    def serve_report(run_id: str, filename: str) -> ResponseReturnValue:
        if not RUN_ID_RE.fullmatch(run_id) or filename not in SERVED_FILES:
            abort(404)
        return send_from_directory(out_dir / run_id, filename)

    return app


def main() -> None:
    create_app().run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()