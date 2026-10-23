"""Textual terminal interface for interactive investigations."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar, Literal

from rich.panel import Panel
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    ProgressBar,
    RichLog,
    SelectionList,
    Static,
)
from textual.widgets.option_list import Option
from textual.widgets.selection_list import Selection

from osint_tool.config import ConfigError, load_settings
from osint_tool.models import ModuleResult, Report, Status, Target
from osint_tool.registry import Module, all_modules, applicable_modules
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.validation import ValidationError, build_target

OutputFormat = Literal["json", "html", "all"]

BANNER = r"""
  ___  ____ ___ _   _ _____
 / _ \/ ___|_ _| \ | |_   _|
| | | \___ \| ||  \| | | |
| |_| |___) | || |\  | | |
 \___/|____/___|_| \_| |_|
"""

FIELDS = {
    "email": "Correo electrónico",
    "username": "Nombre de usuario",
    "domain": "Dominio (ejemplo.com)",
    "phone": "Teléfono internacional (+34600000000)",
    "name": "Nombre de persona",
}
STATUS_STYLES = {Status.OK: "green", Status.SKIPPED: "yellow", Status.ERROR: "red"}


class FlowScreen(Screen[None]):
    """Screen that returns to the main menu with Escape."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "menu", "Menú")
    ]

    @property
    def osint_app(self) -> OsintApp:
        app = self.app
        if not isinstance(app, OsintApp):
            raise RuntimeError("Esta pantalla requiere OsintApp.")
        return app

    def action_menu(self) -> None:
        self.app.switch_screen(MenuScreen())


class MenuScreen(Screen[None]):
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "app.quit", "Salir")
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(Panel(Text(BANNER, style="bold cyan"), border_style="magenta"))
        yield Label("¿Qué quieres hacer?")
        yield OptionList(
            Option("Iniciar una investigación", id="scan"),
            Option("Ver módulos disponibles", id="modules"),
            Option("Salir", id="exit"),
        )
        yield Static(LEGAL_NOTICE)
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id == "scan":
            self.app.switch_screen(TargetScreen())
        elif event.option_id == "modules":
            self.app.switch_screen(ModuleListScreen())
        else:
            self.app.exit()


class ModuleListScreen(FlowScreen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable[str]()
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Módulo", "Datos aceptados")
        for name, module in sorted(all_modules().items()):
            table.add_row(name, ", ".join(sorted(module.accepts)))


class TargetScreen(FlowScreen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Rellena los datos que quieras investigar (deja vacíos los demás)")
        for field, label in FIELDS.items():
            yield Input(placeholder=label, id=field)
        yield Static("", id="error")
        yield Button("Continuar", id="next", variant="primary")
        yield Footer()

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        values = {field: self.query_one(f"#{field}", Input).value for field in FIELDS}
        try:
            target = build_target(
                email=values["email"],
                username=values["username"],
                domain=values["domain"],
                phone=values["phone"],
                name=values["name"],
            )
        except ValidationError as exc:
            self.query_one("#error", Static).update(Text(str(exc), style="bold yellow"))
            return
        self.app.switch_screen(ModulesScreen(target))


class ModulesScreen(FlowScreen):
    def __init__(self, target: Target) -> None:
        super().__init__()
        self._target = target

    def compose(self) -> ComposeResult:
        provided = self._target.provided()
        modules = applicable_modules(self._target)
        yield Header()
        yield Label("Módulos (espacio para marcar/desmarcar)")
        if modules:
            yield SelectionList[str](
                *(
                    Selection(
                        f"{module.name} ({', '.join(sorted(module.accepts & provided))})",
                        module.name,
                        True,
                    )
                    for module in modules
                )
            )
        else:
            yield Static("No hay módulos disponibles para los datos indicados.")
        with Horizontal():
            yield Button("Iniciar consultas", id="start", variant="success", disabled=not modules)
            yield Button("Cancelar", id="cancel", variant="error")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.action_menu()
            return

        names = list(self.query_one(SelectionList).selected)
        if not names:
            self.notify("Selecciona al menos un módulo.", severity="warning")
            return

        try:
            output_dir = load_settings().output_dir
        except ConfigError as exc:
            self.notify(f"Error: {exc}", severity="error")
            return
        modules = applicable_modules(self._target, names)
        self.app.switch_screen(
            RunScreen(self._target, modules, output_dir, self.osint_app.output_format)
        )


class RunScreen(FlowScreen):
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = []

    def __init__(
        self,
        target: Target,
        modules: list[Module],
        output_dir: Path,
        output_format: OutputFormat,
    ) -> None:
        super().__init__()
        self._target = target
        self._modules = modules
        self._output_dir = output_dir
        self._output_format = output_format

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(f"Consultando {len(self._modules)} módulo(s)…")
        yield ProgressBar(total=len(self._modules), show_eta=False)
        yield Static("Preparando fuentes…", id="module-progress")
        yield RichLog(markup=True)
        yield Button("Volver al menú", id="menu", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.investigate()

    @work(thread=True)
    def investigate(self) -> None:
        def notify_progress(result: ModuleResult, _completed: int, _total: int) -> None:
            self.app.call_from_thread(self._advance, result)

        def notify_module_progress(name: str, completed: int, total: int) -> None:
            self.app.call_from_thread(self._show_module_progress, name, completed, total)

        try:
            report = run_investigation(
                self._target,
                self._modules,
                on_progress=notify_progress,
                on_module_progress=notify_module_progress,
            )
            directory, paths = write_reports(
                report, self._output_dir, self._output_format
            )
        except OSError as exc:
            self.app.call_from_thread(self._show_error, f"Error al escribir el informe: {exc}")
            return
        self.app.call_from_thread(
            self.app.switch_screen, ResultScreen(report, directory, paths)
        )

    def _advance(self, result: ModuleResult) -> None:
        color = STATUS_STYLES[result.status]
        self.query_one(ProgressBar).advance(1)
        self.query_one(RichLog).write(
            f"[{color}]{result.status.value:<8}[/] {result.name:<12} "
            f"{len(result.findings)} hallazgos ({result.duration:.1f} s)"
        )

    def _show_module_progress(self, name: str, completed: int, total: int) -> None:
        if total:
            self.query_one("#module-progress", Static).update(
                f"{name}: {completed}/{total} sitios comprobados"
            )
        else:
            self.query_one("#module-progress", Static).update(f"Consultando {name}…")

    def _show_error(self, message: str) -> None:
        self.query_one(RichLog).write(f"[bold red]{message}[/]")
        self.query_one("#menu", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "menu":
            self.action_menu()


class ResultScreen(FlowScreen):
    def __init__(self, report: Report, directory: Path, paths: list[Path]) -> None:
        super().__init__()
        self._report = report
        self._directory = directory
        self._paths = paths

    def compose(self) -> ComposeResult:
        findings = sum(len(result.findings) for result in self._report.results)
        yield Header()
        yield Static(
            Panel(
                f"{len(self._report.results)} módulos · {findings} hallazgos · "
                f"{len(self._report.relations)} relaciones",
                title="Investigación completada",
                border_style="cyan",
            )
        )
        yield Label("Hallazgos")
        if findings:
            yield DataTable[Text | str](id="findings")
        else:
            yield Static("No se encontraron hallazgos.")
        if self._report.relations:
            yield Label("Relaciones (hipótesis; verificar con evidencia independiente)")
            yield DataTable[Text | str](id="relations")
        else:
            yield Static("No se encontraron relaciones.")
        yield Label("Resumen por módulo")
        yield DataTable[Text | str](id="modules")
        yield Static(f"Informes: {self._directory}")
        for note in self._report.notes:
            yield Static(Text(f"Aviso: {note}", style="yellow"))
        yield Label("Esc: volver al menú")
        yield Footer()

    def on_mount(self) -> None:
        if self._report.findings:
            findings_table = self.query_one("#findings", DataTable)
            findings_table.add_columns(
                "Módulo", "Tipo", "Valor", "Fuente", "Detalle", "Confianza"
            )
            for result in self._report.results:
                for finding in result.findings:
                    findings_table.add_row(
                        result.name,
                        finding.type,
                        finding.value,
                        finding.source,
                        finding.detail or "",
                        f"{finding.confidence:.2f}",
                    )

        if self._report.relations:
            relations_table = self.query_one("#relations", DataTable)
            relations_table.add_columns(
                "Origen", "Destino", "Relación", "Evidencia", "Confianza"
            )
            for relation in self._report.relations:
                relations_table.add_row(
                    relation.source,
                    relation.target,
                    relation.label,
                    ", ".join(relation.evidence) or "No especificada",
                    f"{relation.confidence:.2f}",
                )

        modules_table = self.query_one("#modules", DataTable)
        modules_table.add_columns("Módulo", "Estado", "Hallazgos", "Duración", "Detalle")
        for result in self._report.results:
            modules_table.add_row(
                result.name,
                Text(result.status.value, style=STATUS_STYLES[result.status]),
                str(len(result.findings)),
                f"{result.duration:.1f} s",
                result.error or "",
            )


class OsintApp(App[None]):
    TITLE = "OSINT Tool"

    def __init__(self, output_format: OutputFormat = "all") -> None:
        super().__init__()
        self.output_format = output_format

    def on_mount(self) -> None:
        self.push_screen(MenuScreen())


def run(output_format: OutputFormat = "all") -> None:
    logging.getLogger("osint_tool").addHandler(logging.NullHandler())
    OsintApp(output_format).run()
