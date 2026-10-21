"""Contrato de los reporters y utilidades comunes."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Protocol

from osint_tool.models import Report

LEGAL_NOTICE = (
    "Uso responsable: solo con fines educativos, con datos propios o ficticios, "
    "y respetando los términos de servicio de cada fuente y el RGPD. "
    "Los informes pueden contener datos personales: guárdalos de forma segura y "
    "elimínalos cuando dejen de ser necesarios."
)


class Reporter(Protocol):
    """Genera uno o varios ficheros a partir de un `Report`."""

    name: str

    def write(self, report: Report, directory: Path) -> list[Path]:
        """Escribe los ficheros en `directory` y devuelve sus rutas."""
        ...


def create_report_dir(output_dir: Path, report: Report) -> Path:
    """Crea una carpeta nueva y única: <output_dir>/<fecha>-<sufijo>.

    El sufijo aleatorio evita que dos peticiones simultáneas (p. ej. en la
    web) escriban en la misma carpeta, y que una ejecución pise a otra.
    """
    stamp = report.created_at.strftime("%Y%m%dT%H%M%S")
    directory = output_dir / f"{stamp}-{uuid.uuid4().hex[:6]}"
    directory.mkdir(parents=True, exist_ok=False)
    return directory