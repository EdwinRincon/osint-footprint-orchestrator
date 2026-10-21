"""Ejecución segura de herramientas externas (theHarvester, Recon-ng...)."""

from __future__ import annotations

import subprocess  # noqa: S404  (se usa siempre con lista y shell=False)
from collections.abc import Sequence
from dataclasses import dataclass

from osint_tool.config import load_settings


class CliError(RuntimeError):
    """Fallo al ejecutar una herramienta externa (p. ej. timeout)."""


class ToolNotFoundError(CliError):
    """La herramienta no está instalada; el módulo debe marcarse como `skipped`."""


@dataclass(frozen=True)
class CliResult:
    """Salida de un comando."""

    returncode: int
    stdout: str
    stderr: str


def run_cli(args: Sequence[str], *, timeout: int | None = None) -> CliResult:
    """Ejecuta un comando y devuelve su salida.

    Seguridad: `args` debe ser una lista (nunca un string) y se ejecuta con
    `shell=False`, así que `;`, `&&` o `$()` no se interpretan. Quien llame
    debe haber validado antes los datos que coloque en la lista.

    Un código de salida distinto de 0 no lanza error: lo decide quien llama.

    Raises:
        TypeError: si `args` es un string.
        ValueError: si `args` está vacío.
        ToolNotFoundError: si el ejecutable no existe.
        CliError: si se supera el timeout.
    """
    if isinstance(args, str):
        raise TypeError("run_cli necesita una lista de argumentos, no un string")
    if not args:
        raise ValueError("run_cli necesita al menos el ejecutable")
    if timeout is None:
        timeout = load_settings().cli_timeout

    try:
        proc = subprocess.run(  # noqa: S603
            list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"No se encuentra la herramienta: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CliError(f"{args[0]} superó el timeout de {timeout}s") from exc

    return CliResult(proc.returncode, proc.stdout, proc.stderr)