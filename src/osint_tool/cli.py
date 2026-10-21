"""Interfaz de línea de comandos: lee argumentos y delega en el servicio."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from osint_tool import __version__
from osint_tool.config import ConfigError, load_settings
from osint_tool.models import Report
from osint_tool.registry import UnknownModuleError, all_modules, applicable_modules
from osint_tool.reporters import FORMATS, write_reports
from osint_tool.reporters.base import LEGAL_NOTICE

# Importar el servicio registra todos los módulos (necesario para --list-modules).
from osint_tool.service import run_investigation
from osint_tool.validation import ValidationError, build_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint",
        description="Recopila información pública a partir de uno o varios datos.",
        epilog=LEGAL_NOTICE,
    )
    parser.add_argument("--email", help="correo electrónico")
    parser.add_argument("--username", help="nombre de usuario")
    parser.add_argument("--domain", help="dominio, p. ej. ejemplo.com")
    parser.add_argument("--phone", help="teléfono en formato internacional, p. ej. +34600000000")
    parser.add_argument("--name", help="nombre de la persona")
    parser.add_argument("--modules", help="módulos a ejecutar, separados por comas")
    parser.add_argument("--format", choices=FORMATS, default="all", help="formato del informe")
    parser.add_argument("--list-modules", action="store_true", help="lista los módulos y salir")
    parser.add_argument("-v", "--verbose", action="store_true", help="muestra más detalle")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def format_modules() -> str:
    """Una línea por módulo registrado, con las entradas que acepta."""
    modules = all_modules()
    return "\n".join(
        f"{name:<12} {', '.join(sorted(modules[name].accepts))}" for name in sorted(modules)
    )


def format_summary(report: Report, directory: Path, paths: Sequence[Path]) -> str:
    """Resumen legible de la ejecución para la terminal."""
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


def _split(value: str | None) -> list[str] | None:
    """'a, b' -> ['a', 'b']; None si no se indicó nada."""
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    # urllib3 registra las URLs completas en sus avisos: llevarían datos personales al log.
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    if args.list_modules:
        print(format_modules())
        return 0

    try:
        target = build_target(
            email=args.email,
            username=args.username,
            domain=args.domain,
            phone=args.phone,
            name=args.name,
        )
        modules = applicable_modules(target, _split(args.modules))
        output_dir = load_settings().output_dir
    except (ValidationError, UnknownModuleError, ConfigError) as exc:
        parser.error(str(exc))  # imprime el uso y termina con código 2

    if not modules:
        print("Aviso: ningún módulo acepta los datos indicados.", file=sys.stderr)

    report = run_investigation(target, modules)
    try:
        directory, paths = write_reports(report, output_dir, args.format)
    except OSError as exc:
        print(f"Error al escribir el informe: {exc}", file=sys.stderr)
        return 1

    print(format_summary(report, directory, paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())