"""Typer-based terminal interface for investigations and module discovery."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from csv import writer
from io import StringIO
from pathlib import Path
from typing import Annotated, Literal

import typer
from click.exceptions import ClickException
from InquirerPy.prompts.checkbox import CheckboxPrompt
from InquirerPy.prompts.confirm import ConfirmPrompt
from InquirerPy.prompts.input import InputPrompt
from InquirerPy.prompts.list import ListPrompt
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint_tool import __version__
from osint_tool.config import ConfigError, load_settings
from osint_tool.models import Report, Status, Target
from osint_tool.registry import (
    Module,
    UnknownModuleError,
    all_modules,
    applicable_modules,
)
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.validation import (
    ValidationError,
    build_target,
    validate_domain,
    validate_email,
    validate_name,
    validate_phone,
    validate_username,
)

app = typer.Typer(
    name="osint",
    help="Recopila información pública a partir de uno o varios datos.",
    epilog=LEGAL_NOTICE,
)
console = Console(highlight=False)
error_console = Console(stderr=True, highlight=False)
status_console = Console(stderr=True, highlight=False)
INTERRUPTED_EXIT_CODE = 130
_TARGET_LABELS = {
    "email": "Correo electrónico",
    "username": "Nombre de usuario",
    "domain": "Dominio",
    "phone": "Teléfono internacional",
    "name": "Nombre de persona",
}
_TARGET_VALIDATORS: dict[str, Callable[[str], str]] = {
    "email": validate_email,
    "username": validate_username,
    "domain": validate_domain,
    "phone": validate_phone,
    "name": validate_name,
}


def format_modules() -> str:
    """Una línea por módulo registrado, con las entradas que acepta."""
    modules = all_modules()
    return "\n".join(
        f"{name:<12} {', '.join(sorted(modules[name].accepts))}" for name in sorted(modules)
    )


def format_summary(report: Report, directory: Path, paths: Sequence[Path]) -> str:
    """Resumen de texto sin estilos, útil también para consumidores no interactivos."""
    target = ", ".join(f"{key}={value}" for key, value in report.target.to_dict().items())
    lines = [f"Objetivo: {target}", "Fuentes:"]
    for result in report.results:
        detail = f"  {result.error}" if result.error else ""
        lines.append(
            f"  {result.name:<12} {result.status.value:<8} "
            f"{len(result.findings):>3} hallazgos  ({result.duration:.1f} s){detail}"
        )
    lines.append(f"Relaciones: {len(report.relations)}")
    lines.append(f"Informe guardado en: {directory}")
    lines.extend(f"  {path.name}" for path in paths)
    return "\n".join(lines)


def _count_label(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _print_modules() -> None:
    modules = all_modules()
    table = Table(title="Módulos disponibles", header_style="bold cyan")
    table.add_column("Módulo", style="bold")
    table.add_column("Datos aceptados")
    for name in sorted(modules):
        table.add_row(name, ", ".join(sorted(modules[name].accepts)))
    console.print(table)


def _print_summary(report: Report, directory: Path, paths: Sequence[Path]) -> None:
    target = ", ".join(f"{key}={value}" for key, value in report.target.to_dict().items())
    findings = sum(len(result.findings) for result in report.results)
    summary = (
        f"{target}\n\n"
        f"[bold]{_count_label(len(report.results), 'módulo', 'módulos')}[/] · "
        f"[bold]{_count_label(findings, 'hallazgo', 'hallazgos')}[/] · "
        f"[bold]{_count_label(len(report.relations), 'relación', 'relaciones')}[/]"
    )
    console.print(
        Panel(summary, title="Investigación completada", border_style="cyan")
    )

    table = Table(title="Estado por módulo", show_header=True, header_style="bold")
    table.add_column("Módulo")
    table.add_column("Estado")
    table.add_column("Hallazgos", justify="right")
    table.add_column("Duración", justify="right")
    table.add_column("Detalle")
    status_styles = {
        Status.OK: "green",
        Status.SKIPPED: "yellow",
        Status.ERROR: "red",
    }
    for result in report.results:
        table.add_row(
            result.name,
            f"[{status_styles[result.status]}]{result.status.value}[/]",
            str(len(result.findings)),
            f"{result.duration:.1f} s",
            result.error or "",
        )
    console.print(table)
    console.print(f"Informes: [bold]{directory}[/]")
    for path in paths:
        console.print(f"  {path.name}")
    for note in report.notes:
        console.print(f"[yellow]Aviso:[/] {note}")


def _print_quiet_summary(report: Report, directory: Path) -> None:
    findings = sum(len(result.findings) for result in report.results)
    errors = sum(result.status == Status.ERROR for result in report.results)
    skipped = sum(result.status == Status.SKIPPED for result in report.results)
    console.print(
        f"{_count_label(len(report.results), 'módulo', 'módulos')} · "
        f"{_count_label(findings, 'hallazgo', 'hallazgos')} · "
        f"{_count_label(errors, 'error', 'errores')} · "
        f"{_count_label(skipped, 'omitido', 'omitidos')}"
    )
    console.print(f"Informes: {directory}")


def _format_csv_summary(report: Report) -> str:
    output = StringIO(newline="")
    csv_writer = writer(output, lineterminator="\n")
    csv_writer.writerow(("module", "status", "findings", "duration_seconds", "error"))
    for result in report.results:
        csv_writer.writerow(
            (
                result.name,
                result.status.value,
                len(result.findings),
                f"{result.duration:.3f}",
                result.error or "",
            )
        )
    return output.getvalue()


def _print_output(
    report: Report,
    directory: Path,
    paths: Sequence[Path],
    output: Literal["text", "json", "csv"],
    quiet: bool,
) -> None:
    if output == "json":
        typer.echo(
            json.dumps(
                {"notice": LEGAL_NOTICE, **report.to_dict()},
                indent=2,
                ensure_ascii=False,
            )
        )
    elif output == "csv":
        typer.echo(_format_csv_summary(report), nl=False)
    elif quiet:
        _print_quiet_summary(report, directory)
    else:
        _print_summary(report, directory, paths)


def _split(value: str | None) -> list[str] | None:
    """'a, b' -> ['a', 'b']; None si no se indicó nada."""
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _select_modules(target: Target) -> list[str]:
    modules = applicable_modules(target)
    if not modules:
        return []
    choices = [
        {
            "name": f"{module.name} ({', '.join(sorted(module.accepts & target.provided()))})",
            "value": module.name,
            "enabled": True,
        }
        for module in modules
    ]
    selected = CheckboxPrompt(
        message=(
            "Selecciona módulos (flechas para moverte, espacio para marcar, "
            "Enter para seguir):"
        ),
        choices=choices,
    ).execute()
    return list(selected)


def _select_target_fields() -> list[str]:
    choices = [
        {"name": label, "value": field}
        for field, label in _TARGET_LABELS.items()
    ]
    selected = CheckboxPrompt(
        message="¿Qué datos quieres investigar? (flechas para moverte, espacio para elegir)",
        choices=choices,
    ).execute()
    return list(selected)


def _prompt_target() -> Target:
    while True:
        selected_fields = _select_target_fields()
        if selected_fields:
            break
        error_console.print("[yellow]Selecciona al menos un tipo de dato.[/]")

    values: dict[str, str] = {}
    for field in selected_fields:
        label = _TARGET_LABELS[field]
        while True:
            value = InputPrompt(message=f"{label}:").execute()
            try:
                _TARGET_VALIDATORS[field](value)
            except ValidationError as exc:
                error_console.print(f"[yellow]{exc} Inténtalo de nuevo.[/]")
                continue
            values[field] = value
            break

    return build_target(
        email=values.get("email"),
        username=values.get("username"),
        domain=values.get("domain"),
        phone=values.get("phone"),
        name=values.get("name"),
    )


def _interactive_menu() -> str:
    return str(
        ListPrompt(
            message="¿Qué quieres hacer?",
            choices=[
                {"name": "Iniciar una investigación", "value": "scan"},
                {"name": "Ver módulos disponibles", "value": "modules"},
                {"name": "Salir", "value": "exit"},
            ],
            default="scan",
        ).execute()
    )


def _select_and_confirm_modules(target: Target) -> list[Module]:
    selected_names = _select_modules(target)
    if not selected_names:
        console.print(
            "[yellow]No hay módulos seleccionados; no se consultó ninguna fuente.[/]"
        )
        raise typer.Exit()
    selected_modules = applicable_modules(target, selected_names)
    confirmed = ConfirmPrompt(
        message="¿Iniciar consultas a las fuentes seleccionadas?",
        default=False,
    ).execute()
    if not confirmed:
        console.print("[yellow]Investigación cancelada; no se consultó ninguna fuente.[/]")
        raise typer.Exit()
    return selected_modules


def _supports_interactive_prompts() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _run_scan(
    *,
    email: str | None,
    username: str | None,
    domain: str | None,
    phone: str | None,
    name: str | None,
    modules: str | None,
    output_format: Literal["json", "html", "all"],
    output: Literal["text", "json", "csv"],
    interactive: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    try:
        if interactive and modules:
            raise ValidationError("No combines --interactive con --modules.")
        if interactive:
            if not _supports_interactive_prompts():
                raise ValidationError("--interactive requiere una terminal interactiva.")
            try:
                target = (
                    _prompt_target()
                    if not any((email, username, domain, phone, name))
                    else build_target(
                        email=email,
                        username=username,
                        domain=domain,
                        phone=phone,
                        name=name,
                    )
                )
                selected_modules = _select_and_confirm_modules(target)
            except KeyboardInterrupt as exc:
                error_console.print("\n[yellow]Asistente cancelado.[/]")
                raise typer.Exit(code=130) from exc
        else:
            target = build_target(
                email=email,
                username=username,
                domain=domain,
                phone=phone,
                name=name,
            )
            requested_names = _split(modules)
            selected_modules = (
                applicable_modules(target, requested_names)
                if requested_names is not None
                else applicable_modules(target)
            )
        output_dir = load_settings().output_dir
    except (ValidationError, UnknownModuleError, ConfigError) as exc:
        error_console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if not selected_modules:
        error_console.print("[yellow]Aviso:[/] ningún módulo acepta los datos indicados.")

    try:
        status_context = (
            status_console.status(
                f"Consultando {_count_label(len(selected_modules), 'módulo', 'módulos')}…"
            )
            if sys.stderr.isatty() and not quiet
            else nullcontext()
        )
        with status_context:
            report = run_investigation(target, selected_modules)
        directory, paths = write_reports(report, output_dir, output_format)
    except KeyboardInterrupt as exc:
        error_console.print("\n[yellow]Investigación interrumpida.[/]")
        raise typer.Exit(code=130) from exc
    except OSError as exc:
        error_console.print(f"[bold red]Error al escribir el informe:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _print_output(report, directory, paths, output, quiet)

    if any(result.status == Status.ERROR for result in report.results):
        raise typer.Exit(code=1)


def _root_options(
    email: Annotated[str | None, typer.Option(help="Correo electrónico.")] = None,
    username: Annotated[str | None, typer.Option(help="Nombre de usuario.")] = None,
    domain: Annotated[str | None, typer.Option(help="Dominio, por ejemplo ejemplo.com.")] = None,
    phone: Annotated[
        str | None,
        typer.Option(help="Teléfono internacional, por ejemplo +34600000000."),
    ] = None,
    name: Annotated[str | None, typer.Option(help="Nombre de la persona.")] = None,
    modules: Annotated[str | None, typer.Option(help="Módulos separados por comas.")] = None,
    output_format: Annotated[
        Literal["json", "html", "all"],
        typer.Option("--format", help="Formato del informe."),
    ] = "all",
    output: Annotated[
        Literal["text", "json", "csv"],
        typer.Option(
            "--output",
            help="Salida por terminal: resumen legible, informe JSON o resumen CSV.",
        ),
    ] = "text",
    list_modules: Annotated[
        bool, typer.Option("--list-modules", help="Lista los módulos y salir.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Muestra más detalle.")] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Resumen compacto y sin indicador de progreso."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", help="Muestra la versión."),
    ] = False,
) -> None:
    """Ejecuta la CLI interactiva o procesa opciones explícitas para automatización."""
    if version:
        typer.echo(f"osint {__version__}")
        raise typer.Exit()
    if list_modules:
        _print_modules()
        return
    if any((email, username, domain, phone, name)) or modules is not None:
        _run_scan(
            email=email,
            username=username,
            domain=domain,
            phone=phone,
            name=name,
            modules=modules,
            output_format=output_format,
            output=output,
            interactive=False,
            verbose=verbose,
            quiet=quiet,
        )
        return
    if not _supports_interactive_prompts():
        _run_scan(
            email=None,
            username=None,
            domain=None,
            phone=None,
            name=None,
            modules=None,
            output_format=output_format,
            output=output,
            interactive=False,
            verbose=verbose,
            quiet=quiet,
        )
        return

    while True:
        try:
            action = _interactive_menu()
        except KeyboardInterrupt as exc:
            error_console.print("\n[yellow]Asistente cancelado.[/]")
            raise typer.Exit(code=130) from exc
        if action == "exit":
            return
        if action == "modules":
            _print_modules()
            continue
        try:
            _run_scan(
                email=None,
                username=None,
                domain=None,
                phone=None,
                name=None,
                modules=None,
                output_format=output_format,
                output=output,
                interactive=True,
                verbose=verbose,
                quiet=quiet,
            )
        except typer.Exit as exc:
            if exc.exit_code == INTERRUPTED_EXIT_CODE:
                raise


app.command()(_root_options)


def main(argv: Sequence[str] | None = None) -> int:
    """Ejecuta la aplicación; `argv` permite llamar y probar la CLI desde Python."""
    command = typer.main.get_command(app)
    try:
        result = command.main(
            args=list(argv) if argv is not None else None,
            prog_name="osint",
            standalone_mode=False,
        )
    except typer.Exit as exc:
        if exc.exit_code:
            raise SystemExit(exc.exit_code) from exc
        return exc.exit_code
    except Exception as exc:
        if not isinstance(exc, ClickException):
            raise
        exc.show()
        raise SystemExit(exc.exit_code) from exc
    exit_code = int(result or 0)
    if exit_code:
        raise SystemExit(exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
