"""Informe en JSON: datos completos y estado de cada módulo."""

from __future__ import annotations

import json
from pathlib import Path

from osint_tool.models import Report
from osint_tool.reporters.base import LEGAL_NOTICE, write_private_text


class JsonReporter:
    """Escribe `report.json` con el aviso de uso responsable al inicio."""

    name = "json"

    # JSON conserva los campos estructurados para análisis automatizado posterior.
    def write(self, report: Report, directory: Path) -> list[Path]:
        path = directory / "report.json"
        data = {"notice": LEGAL_NOTICE, **report.to_dict()}
        # ensure_ascii=False conserva tildes y ñ legibles en el fichero.
        write_private_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return [path]