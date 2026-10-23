"""Formatos de salida disponibles y escritura conjunta del informe."""

from __future__ import annotations

from pathlib import Path

from osint_tool.models import Report
from osint_tool.reporters.base import Reporter, create_report_dir
from osint_tool.reporters.graph import GraphReporter
from osint_tool.reporters.html_reporter import HtmlReporter
from osint_tool.reporters.json_reporter import JsonReporter

__all__ = ["FORMATS", "reporters_for", "write_reports"]

FORMATS = ("json", "html", "all")


def reporters_for(fmt: str) -> list[Reporter]:
    """Reporters de un formato. El HTML incluye el grafo si sus recursos están disponibles."""
    if fmt == "json":
        return [JsonReporter()]
    if fmt == "html":
        return [GraphReporter(), HtmlReporter()]
    if fmt == "all":
        return [GraphReporter(), HtmlReporter(), JsonReporter()]
    raise ValueError(f"Formato desconocido: {fmt}. Disponibles: {', '.join(FORMATS)}")


def write_reports(report: Report, output_dir: Path, fmt: str = "all") -> tuple[Path, list[Path]]:
    """Crea la carpeta del informe, escribe los ficheros y devuelve (carpeta, rutas)."""
    reporters = reporters_for(fmt)  # valida el formato antes de crear nada
    directory = create_report_dir(output_dir, report)
    paths = [path for reporter in reporters for path in reporter.write(report, directory)]
    return directory, paths