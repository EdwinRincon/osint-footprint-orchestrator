"""Informe JSON con resultados estructurados y sin payloads `raw`."""

from __future__ import annotations

import json
from pathlib import Path

from osint_tool.models import Report
from osint_tool.reporters.base import LEGAL_NOTICE, write_private_text


class JsonReporter:
    """Escribe `report.json` sin payloads `raw` y con el aviso de uso responsable."""

    name = "json"

    # Omitir payloads de origen evita persistir respuestas potencialmente sensibles por defecto.
    def write(self, report: Report, directory: Path) -> list[Path]:
        path = directory / "report.json"
        report_data = report.to_dict()
        for result in report_data["results"]:
            for finding in result["findings"]:
                finding.pop("raw", None)
        data = {"notice": LEGAL_NOTICE, **report_data}
        # ensure_ascii=False conserva tildes y ñ legibles en el fichero.
        write_private_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return [path]