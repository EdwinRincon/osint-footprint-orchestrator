"""Contrato de los reporters y utilidades comunes."""

from __future__ import annotations

import os
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
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


class Reporter(Protocol):
    """Genera uno o varios ficheros a partir de un `Report`."""

    name: str

    # El contrato común permite combinar formatos sin conocer sus implementaciones.
    def write(self, report: Report, directory: Path) -> list[Path]:
        """Escribe los ficheros en `directory` y devuelve sus rutas."""
        ...


def ensure_private_directory(directory: Path) -> None:
    """Create missing path components with private permissions."""
    missing: list[Path] = []
    current = directory
    while not current.exists():
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        path.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        path.chmod(PRIVATE_DIRECTORY_MODE)


def set_private_permissions(path: Path, mode: int) -> None:
    """Set a generated file or directory to an explicit private mode."""
    path.chmod(mode)


def write_private_text(path: Path, content: str, *, exclusive: bool = False) -> None:
    """Write UTF-8 text with private permissions, including when replacing a file."""
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), PRIVATE_FILE_MODE)
        handle.write(content)


# Un sufijo único impide que ejecuciones concurrentes sobrescriban evidencia anterior.
def create_report_dir(output_dir: Path, report: Report) -> Path:
    """Crea una carpeta nueva y única: <output_dir>/<fecha>-<sufijo>.

    El sufijo aleatorio evita que dos peticiones simultáneas (p. ej. en la
    web) escriban en la misma carpeta, y que una ejecución pise a otra.
    """
    ensure_private_directory(output_dir)
    stamp = report.created_at.strftime("%Y%m%dT%H%M%S")
    directory = output_dir / f"{stamp}-{uuid.uuid4().hex[:6]}"
    directory.mkdir(mode=PRIVATE_DIRECTORY_MODE, exist_ok=False)
    set_private_permissions(directory, PRIVATE_DIRECTORY_MODE)
    return directory