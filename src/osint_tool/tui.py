"""Textual terminal interface for interactive investigations."""

from __future__ import annotations

import logging
import webbrowser
from pathlib import Path
from threading import Thread
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
from werkzeug.serving import BaseWSGIServer, make_server

from osint_tool.config import ConfigError, load_settings
from osint_tool.models import ModuleResult, Report, Status, Target
from osint_tool.registry import Module, all_modules, applicable_modules
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.validation import ValidationError, build_target
from osint_tool.web.app import HOST, PORT, create_app

OutputFormat = Literal["json", "html", "all"]

BANNER = r"""
 _____ _____ _____ _   _ ___________  _____________   __
|  _  /  ___|_   _| \ | |_   _| ___ \|  _  |  _  \ \ / /
| | | \ `--.  | | |  \| | | | | |_/ /| | | | | | |\ V /
| | | |`--. \ | | | . ` | | | | ___ \| | | | | | | \ /
\ \_/ /\__/ /_| |_| |\  | | | | |_/ /\ \_/ / |/ /  | |
 \___/\____/ \___/\_| \_/ \_/ \____/  \___/|___/   \_/
"""

FIELDS = {
    "email": "Correo electrónico",
    "username": "Nombre de usuario",
    "domain": "Dominio (ejemplo.com)",
    "phone": "Teléfono (E.164 o número nacional)",
    "phone_region": "Región del teléfono (ISO, p. ej. US, GB, CO)",
    "name": "Nombre de persona",
}
STATUS_STYLES = {Status.OK: "green", Status.SKIPPED: "yellow", Status.ERROR: "red"}


class FlowScreen(Screen[None]):
    """Screen that returns to the main menu with Escape."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "menu", "Menú")
    ]

    # Validar el tipo de aplicación evita fallos crípticos si la pantalla se reutiliza mal.
    @property
    def osint_app(self) -> OsintApp:
        app = self.app
        if not isinstance(app, OsintApp):
            raise RuntimeError("Esta pantalla requiere OsintApp.")
        return app

    # Centralizar el retorno mantiene el mismo destino para Escape y los botones de navegación.
    def action_menu(self) -> None:
        self.app.switch_screen(MenuScreen())


class MenuScreen(Screen[None]):
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "app.quit", "Salir")
    ]

    # Definir las opciones aquí mantiene navegación y presentación como una sola pantalla.
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(Panel(Text(BANNER, style="bold cyan"), border_style="magenta"))
        yield Label("¿Qué quieres hacer?")
        yield OptionList(
            Option("Iniciar una investigación", id="scan"),
            Option("Ver módulos disponibles", id="modules"),
            Option("Abrir sitio web", id="website"),
            Option("Salir", id="exit"),
        )
        yield Static(LEGAL_NOTICE)
        yield Footer()

    # Resolver por ID desacopla las acciones del texto visible y su localización.
    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id == "scan":
            self.app.switch_screen(TargetScreen())
        elif event.option_id == "modules":
            self.app.switch_screen(ModuleListScreen())
        elif event.option_id == "website":
            if isinstance(self.app, OsintApp):
                self.app.open_website()
        else:
            self.app.exit()


class ModuleListScreen(FlowScreen):
    # Mantener el contenedor mínimo permite cargar el catálogo desde el registro actual.
    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable[str]()
        yield Footer()

    # Leer el registro al montar evita duplicar la lista de módulos en la interfaz.
    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Módulo", "Datos aceptados")
        for name, module in sorted(all_modules().items()):
            table.add_row(name, ", ".join(sorted(module.accepts)))


class TargetScreen(FlowScreen):
    # Generar campos desde FIELDS evita que la interfaz diverja del modelo de entrada.
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Rellena los datos que quieras investigar (deja vacíos los demás)")
        for field, label in FIELDS.items():
            yield Input(placeholder=label, id=field)
        yield Static("", id="error")
        yield Button("Continuar", id="next", variant="primary")
        yield Footer()

    # Validar antes de avanzar evita iniciar consultas con datos incompletos o mal formados.
    def on_button_pressed(self, _event: Button.Pressed) -> None:
        values = {field: self.query_one(f"#{field}", Input).value for field in FIELDS}
        try:
            target = build_target(
                email=values["email"],
                username=values["username"],
                domain=values["domain"],
                phone=values["phone"],
                phone_region=values["phone_region"],
                name=values["name"],
            )
        except ValidationError as exc:
            self.query_one("#error", Static).update(Text(str(exc), style="bold yellow"))
            return
        self.app.switch_screen(ModulesScreen(target))


def _module_selection(module: Module, provided: frozenset[str]) -> Selection[str]:
    network = getattr(module, "requires_network", False)
    source_kind = "externa; opt-in" if network else "local"
    accepted_inputs = ", ".join(sorted(module.accepts & provided))
    label = getattr(module, "web_label", module.name)
    return Selection(
        f"{label} [{source_kind}] ({accepted_inputs})",
        module.name,
        not network,
    )


class ModulesScreen(FlowScreen):
    # Conservar el objetivo en la pantalla permite cambiar selección sin reconstruir entradas.
    def __init__(self, target: Target) -> None:
        super().__init__()
        self._target = target

    # Mostrar solo módulos aplicables evita prometer consultas que no aceptan el objetivo.
    def compose(self) -> ComposeResult:
        provided = self._target.provided()
        modules = applicable_modules(self._target)
        yield Header()
        yield Label("Módulos (espacio para marcar/desmarcar)")
        if modules:
            yield Static(
                "Las fuentes externas están desactivadas inicialmente. Seleccionarlas permite "
                "consultas de red que envían los datos pertinentes a terceros."
            )
            if any(module.name == "breaches" for module in modules):
                yield Static(
                    "Brechas conocidas envía el correo a XposedOrNot "
                    "(2 solicitudes/s, 25/hora, 100/día por endpoint)."
                )
            if any(module.name == "github_name" for module in modules):
                yield Static(
                    "Perfiles de GitHub por nombre envía el nombre a GitHub "
                    "(máximo 10 búsquedas/minuto sin autenticación)."
                )
            if any(module.name == "github_profile" for module in modules):
                yield Static(
                    "Perfil de GitHub por username envía el username a GitHub "
                    "(máximo 60 solicitudes/hora sin autenticación)."
                )
            if any(module.name == "usernames" for module in modules):
                yield Static(
                    "WhatsMyName excluye siempre los sitios de categoría NSFW."
                )
            yield SelectionList[str](
                *(_module_selection(module, provided) for module in modules)
            )
        else:
            yield Static(
                "No hay fuentes disponibles para estos datos; "
                "no se inició ninguna consulta."
            )
        with Horizontal():
            yield Button("Iniciar consultas", id="start", variant="success", disabled=not modules)
            yield Button("Cancelar", id="cancel", variant="error")
        yield Footer()

    # Comprobar selección y configuración antes de iniciar evita ejecuciones mal definidas.
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

    # La pantalla conserva el contexto necesario para informar y persistir el mismo trabajo.
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

    # Preparar controles antes del worker garantiza que su progreso tenga destinos visibles.
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(f"Consultando {len(self._modules)} módulo(s)…")
        yield ProgressBar(total=len(self._modules), show_eta=False)
        yield Static("Preparando fuentes…", id="module-progress")
        yield RichLog(markup=True)
        yield Button("Volver al menú", id="menu", disabled=True)
        yield Footer()

    # Esperar al montaje evita actualizaciones de progreso antes de que existan los widgets.
    def on_mount(self) -> None:
        self.investigate()

    # Ejecutar fuera del hilo de interfaz mantiene la terminal receptiva durante consultas lentas.
    @work(thread=True)
    def investigate(self) -> None:
        # Textual requiere que las actualizaciones de widgets vuelvan al hilo de interfaz.
        def notify_progress(result: ModuleResult, _completed: int, _total: int) -> None:
            self.app.call_from_thread(self._advance, result)

        # Mantener el progreso por fuente visible sin acoplar módulos a Textual.
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

    # Actualizar una fila por módulo mantiene el avance legible sin exponer datos sensibles.
    def _advance(self, result: ModuleResult) -> None:
        color = STATUS_STYLES[result.status]
        self.query_one(ProgressBar).advance(1)
        self.query_one(RichLog).write(
            f"[{color}]{result.status.value:<8}[/] {result.name:<12} "
            f"{len(result.findings)} hallazgos ({result.duration:.1f} s)"
        )

    # El total cero identifica preparación de un módulo que aún no reporta tareas internas.
    def _show_module_progress(self, name: str, completed: int, total: int) -> None:
        if total:
            self.query_one("#module-progress", Static).update(
                f"{name}: {completed}/{total} sitios comprobados"
            )
        else:
            self.query_one("#module-progress", Static).update(f"Consultando {name}…")

    # Habilitar retorno tras un fallo evita dejar al usuario atrapado en una pantalla de espera.
    def _show_error(self, message: str) -> None:
        self.query_one(RichLog).write(f"[bold red]{message}[/]")
        self.query_one("#menu", Button).disabled = False

    # Mantener la navegación por eventos respeta el flujo estándar de Textual.
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "menu":
            self.action_menu()


class ResultScreen(FlowScreen):
    # Agrupar el reporte y sus rutas mantiene visibles los resultados junto a su ubicación guardada.
    def __init__(self, report: Report, directory: Path, paths: list[Path]) -> None:
        super().__init__()
        self._report = report
        self._directory = directory
        self._paths = paths

    # Componer tablas según el contenido evita mostrar paneles vacíos como resultados.
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

    # Poblar tablas tras el montaje asegura que las consultas de widgets ya estén disponibles.
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
    TITLE = "OSINTBODY"

    # Mantener el formato en la aplicación permite que la elección persista durante el flujo.
    def __init__(self, output_format: OutputFormat = "all") -> None:
        super().__init__()
        self.output_format = output_format
        self._web_server: BaseWSGIServer | None = None

    # Crear el servidor de forma diferida evita abrir un puerto si el usuario no pide la web.
    def open_website(self) -> None:
        url = f"http://{HOST}:{PORT}"
        try:
            if self._web_server is None:
                self._web_server = make_server(HOST, PORT, create_app(), threaded=True)
                Thread(target=self._web_server.serve_forever, daemon=True).start()
            if not webbrowser.open(url):
                self.notify(f"No se pudo abrir el navegador. Visita {url}", severity="warning")
        except OSError as exc:
            self.notify(f"No se pudo iniciar el sitio web: {exc}", severity="error")

    # Entrar al menú al montar respeta el ciclo de vida de la aplicación Textual.
    def on_mount(self) -> None:
        self.push_screen(MenuScreen())


# Exponer una sola función de arranque simplifica la integración con CLI y pruebas.
def run(output_format: OutputFormat = "all") -> None:
    logging.getLogger("osint_tool").addHandler(logging.NullHandler())
    OsintApp(output_format).run()
