"""Textual terminal entry point."""

from __future__ import annotations

import sys
from typing import Annotated

import typer

from osint_tool import __version__
from osint_tool.tui import run as run_tui

app = typer.Typer(
    name="osintbody",
    help="Investigación OSINT interactiva para uso educativo y responsable.",
    add_completion=False,
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def main_command(
    version: Annotated[bool, typer.Option("--version", help="Muestra la versión.")] = False,
) -> None:
    """Inicia la interfaz interactiva de terminal."""
    if version:
        typer.echo(f"osintbody {__version__}")
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        typer.echo("La interfaz interactiva requiere una terminal (TTY).", err=True)
        raise typer.Exit(code=2)
    run_tui()


def main(argv: list[str] | None = None) -> int:
    """Ejecuta la interfaz de terminal."""
    command = typer.main.get_command(app)
    try:
        command.main(
            args=argv,
            prog_name="osintbody",
            standalone_mode=True,
        )
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
