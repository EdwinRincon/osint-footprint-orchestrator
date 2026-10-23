"""Informe HTML legible con sus recursos interactivos locales."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from osint_tool.models import Report
from osint_tool.reporters.base import LEGAL_NOTICE

TEMPLATES_DIR = Path(__file__).parent / "templates"

# autoescape=True: todo dato externo (WHOIS, DNS, nombres de brecha...) se escapa.
# StrictUndefined: un error tipográfico en la plantilla falla en vez de salir vacío.
_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True,
    undefined=StrictUndefined,
)


class HtmlReporter:
    """Escribe el informe HTML sin incluir la visualización interactiva del grafo."""

    name = "html"

    def write(self, report: Report, directory: Path) -> list[Path]:
        html = _env.get_template("report.html").render(
            report=report,
            target=report.target.to_dict(),
            notice=LEGAL_NOTICE,
            created=report.created_at.isoformat(timespec="seconds"),
        )
        path = directory / "report.html"
        path.write_text(html, encoding="utf-8")
        return [path]