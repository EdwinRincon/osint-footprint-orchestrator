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
    Checkbox,
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
from osint_tool.models import ModuleResult, Report, SourceCheckStatus, Status, Target
from osint_tool.registry import Module, ModuleSkipped, all_modules, applicable_modules
from osint_tool.reporters import write_reports
from osint_tool.reporters.base import LEGAL_NOTICE
from osint_tool.service import run_investigation
from osint_tool.sessions import (
    EDGE_LABEL,
    EntryStatus,
    InvestigationSession,
    PivotChoice,
    SavedSession,
    SessionError,
    delete_saved_session,
    list_saved_sessions,
    network_recipients,
    safe_evidence_text,
    safe_report,
    safe_source_url,
)
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
        options = [
            Option("Iniciar una investigación", id="scan"),
            Option("Ver módulos disponibles", id="modules"),
            Option("Abrir sitio web", id="website"),
        ]
        if (
            isinstance(self.app, OsintApp)
            and self.app.current_session is not None
            and all(
                entry.status is not EntryStatus.RUNNING
                for entry in self.app.current_session.entries
            )
        ):
            options.append(Option("Continuar sesión actual", id="session"))
        options.append(Option("Historial local", id="manage-sessions"))
        options.append(Option("Salir", id="exit"))
        yield OptionList(*options)
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
        elif event.option_id == "session" and isinstance(self.app, OsintApp):
            if self.app.current_session is not None:
                self.app.switch_screen(SessionResultScreen(self.app.current_session))
        elif event.option_id == "manage-sessions":
            try:
                output_dir = load_settings().output_dir
            except ConfigError as exc:
                self.notify(f"Error: {exc}", severity="error")
            else:
                self.app.switch_screen(SavedSessionsScreen(output_dir))
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
            if any(module.name == "hibp" for module in modules):
                yield Static(
                    "HIBP envía el correo a Have I Been Pwned, un tercero. Requiere "
                    "OSINT_HIBP_API_KEY; sin ella no se consulta la red."
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
            settings = load_settings()
            session = InvestigationSession.create(
                settings.output_dir,
                self._target,
                settings.session_max_depth,
                settings.session_max_targets,
                settings.hibp_api_key,
            )
        except ConfigError as exc:
            self.notify(f"Error: {exc}", severity="error")
            return
        except (OSError, SessionError) as exc:
            self.notify(f"No se pudo crear la sesión ({type(exc).__name__}).", severity="error")
            return
        modules = applicable_modules(self._target, names)
        self.osint_app.current_session = session
        self.app.switch_screen(
            RunScreen(
                self._target,
                modules,
                session,
                "entry-1",
                self.osint_app.output_format,
            )
        )


class RunScreen(FlowScreen):
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = []

    # La pantalla conserva el contexto necesario para informar y persistir el mismo trabajo.
    def __init__(
        self,
        target: Target,
        modules: list[Module],
        session: InvestigationSession,
        entry_id: str,
        output_format: OutputFormat,
    ) -> None:
        super().__init__()
        self._target = target
        self._modules = modules
        self._session = session
        self._entry_id = entry_id
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

        report: Report | None = None
        directory: Path | None = None
        try:
            report = run_investigation(
                self._target,
                self._modules,
                on_progress=notify_progress,
                on_module_progress=notify_module_progress,
            )
            directory, _ = write_reports(
                safe_report(report, self._session.api_key),
                self._session.directory / "reports" / self._entry_id,
                self._output_format,
            )
            self._session.complete_entry(self._entry_id, report, directory)
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "La entrada %s falló (%s)", self._entry_id, type(exc).__name__
            )
            try:
                self._session.fail_entry(
                    self._entry_id,
                    type(exc).__name__,
                    report=report,
                    report_directory=directory,
                )
            except (OSError, SessionError) as persistence_error:
                self.app.call_from_thread(
                    self._show_error,
                    "La entrada falló y no se pudo guardar su estado "
                    f"({type(persistence_error).__name__}).",
                )
                return
        self.app.call_from_thread(
            self.app.switch_screen, SessionResultScreen(self._session)
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
            not_configured = [
                f"{check.source}: {check.status.value}"
                for check in result.source_checks
                if check.status is SourceCheckStatus.NOT_CONFIGURED
            ]
            details = [result.error, *not_configured]
            modules_table.add_row(
                result.name,
                Text(result.status.value, style=STATUS_STYLES[result.status]),
                str(len(result.findings)),
                f"{result.duration:.1f} s",
                "; ".join(detail for detail in details if detail),
            )


class SessionResultScreen(FlowScreen):
    """Local session graph, node status, remaining budget, and next-step actions."""

    def __init__(self, session: InvestigationSession) -> None:
        super().__init__()
        self._session = session

    def compose(self) -> ComposeResult:
        latest = self._session.entries[-1]
        findings = len(latest.report.findings) if latest.report is not None else 0
        yield Header()
        yield Static(
            Panel(
                f"{len(self._session.entries)} objetivo(s) · {findings} hallazgo(s) "
                f"en {latest.entry_id} · estado {latest.status.value}",
                title="Sesión local",
                border_style="cyan",
            )
        )
        yield Static(
            f"Presupuesto restante en la rama más profunda: "
            f"{self._session.remaining_depth} nivel(es); "
            f"{self._session.remaining_targets} objetivo(s). "
            "Cada relación entre objetivos es una hipótesis no verificada."
        )
        yield Label("Nodos")
        yield DataTable[str](id="session-nodes")
        yield Label("Aristas — unverified hypothesis")
        if self._session.edges:
            yield DataTable[str](id="session-edges")
        else:
            yield Static("Aún no hay pivotes seleccionados.")
        if latest.report is not None and latest.report.findings:
            yield Label(f"Hallazgos de {latest.entry_id}")
            yield DataTable[Text | str](id="session-findings")
        elif latest.status is EntryStatus.FAILED:
            yield Static(latest.error or "La entrada falló.")
        else:
            yield Static("Esta entrada no produjo hallazgos.")
        yield Static(f"Informe local: {self._session.directory / 'session.json'}")
        with Horizontal():
            yield Button(
                "Elegir hallazgo para pivot",
                id="pivot",
                disabled=not self._session.pivot_choices(),
            )
            yield Button(
                "Eliminar sesión",
                id="delete",
                variant="error",
                disabled=any(
                    entry.status is EntryStatus.RUNNING for entry in self._session.entries
                ),
            )
            yield Button("Menú", id="menu")
        yield Footer()

    def on_mount(self) -> None:
        nodes = self.query_one("#session-nodes", DataTable)
        nodes.add_columns("Entrada", "Profundidad", "Objetivo", "Estado", "Informe")
        for entry in self._session.entries:
            nodes.add_row(
                entry.entry_id,
                str(entry.depth),
                ", ".join(f"{key}={value}" for key, value in entry.target.to_dict().items()),
                entry.status.value,
                entry.report_directory or "",
            )

        if self._session.edges:
            edges = self.query_one("#session-edges", DataTable)
            edges.add_columns(
                "Padre",
                "Hijo",
                "Módulo",
                "URL de fuente",
                "Evidencia",
                "Confianza",
                "Relación",
            )
            for edge in self._session.edges:
                edges.add_row(
                    edge.parent_entry_id,
                    edge.child_entry_id,
                    edge.source_module,
                    edge.source_url or "",
                    edge.evidence_text,
                    f"{edge.confidence:.2f}",
                    edge.label,
                )

        latest = self._session.entries[-1]
        if latest.report is not None and latest.report.findings:
            findings = self.query_one("#session-findings", DataTable)
            findings.add_columns("Módulo", "Tipo", "Valor", "Fuente", "Evidencia", "Confianza")
            for result in latest.report.results:
                for finding in result.findings:
                    findings.add_row(
                        result.name,
                        finding.entity_type,
                        finding.value,
                        finding.source,
                        finding.detail or "",
                        f"{finding.confidence:.2f}",
                    )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pivot":
            self.app.switch_screen(PivotSelectionScreen(self._session))
        elif event.button.id == "delete":
            self.app.switch_screen(DeleteSessionScreen(self._session))
        elif event.button.id == "menu":
            self.action_menu()


class PivotSelectionScreen(FlowScreen):
    """List only exact, validator-approved values; each target type is an explicit row."""

    def __init__(self, session: InvestigationSession) -> None:
        super().__init__()
        self._session = session
        self._choices = session.pivot_choices()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            "Elige un valor observado y su tipo. Los valores ambiguos aparecen una vez "
            "por cada tipo válido; no se infiere ni transforma ningún identificador."
        )
        yield Static(
            f"Presupuesto en la rama más profunda: "
            f"{self._session.remaining_depth} nivel(es); "
            f"{self._session.remaining_targets} objetivo(s)."
        )
        if self._choices:
            options = []
            for index, choice in enumerate(self._choices):
                evidence = safe_evidence_text(choice.finding.detail, self._session.api_key)
                options.append(
                    Selection(
                        Text(
                            f"{choice.parent_entry_id} (prof. "
                            f"{self._session.entry(choice.parent_entry_id).depth}) · "
                            f"{choice.target_type}="
                            f"{choice.target.to_dict()[choice.target_type]} · "
                            f"{choice.source_module}/{choice.finding.source} · "
                            f"observado: {choice.finding.value} · "
                            f"evidencia: {evidence} · "
                            f"confianza {choice.finding.confidence:.2f}"
                        ),
                        str(index),
                        False,
                    )
                )
            yield SelectionList[str](
                *options,
                id="pivot-choices",
            )
        else:
            yield Static("No hay valores nuevos que pasen los validadores actuales.")
        with Horizontal():
            yield Button("Revisar módulos", id="select", disabled=not self._choices)
            yield Button("Cancelar", id="cancel")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.app.switch_screen(SessionResultScreen(self._session))
            return
        if not self._choices:
            return
        selected = self.query_one("#pivot-choices", SelectionList).selected
        if len(selected) != 1:
            self.notify("Selecciona exactamente un valor y tipo.", severity="warning")
            return
        try:
            choice = self._choices[int(selected[0])]
        except (ValueError, IndexError):
            self.notify("La selección ya no es válida.", severity="error")
            return
        self.app.switch_screen(
            PivotModulesScreen(self._session, choice)
        )


class PivotModulesScreen(FlowScreen):
    """Select modules for one pivot while exposing recipients before confirmation."""

    def __init__(self, session: InvestigationSession, choice: PivotChoice) -> None:
        super().__init__()
        self._session = session
        self._choice = choice
        self._modules = applicable_modules(choice.target)
        self._recipients: dict[str, tuple[str, ...]] = {}
        self._recipient_errors: dict[str, str] = {}
        for module in self._modules:
            recipients, error = _resolve_module_recipients(module)
            if error is not None:
                self._recipient_errors[module.name] = error
            else:
                self._recipients[module.name] = recipients

    def compose(self) -> ComposeResult:
        yield Header()
        value = self._choice.target.to_dict()[self._choice.target_type]
        yield Static(
            f"Objetivo propuesto: {self._choice.target_type}={value}. "
            "Seleccionar módulos no los ejecuta."
        )
        yield Label("Módulos (espacio para marcar/desmarcar)")
        if self._modules:
            yield SelectionList[str](
                *(
                    _module_selection(module, self._choice.target.provided())
                    for module in self._modules
                )
            )
        else:
            yield Static("No hay módulos aplicables a este valor.")
        yield Label("Destinatarios potenciales")
        yield RichLog(id="pivot-recipients", markup=False)
        with Horizontal():
            yield Button("Revisar confirmación", id="review", disabled=not self._modules)
            yield Button("Cancelar", id="cancel")
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#pivot-recipients", RichLog)
        for module in self._modules:
            if not getattr(module, "requires_network", False):
                log.write(f"{module.name}: local; no se envía a terceros.")
                continue
            if module.name in self._recipient_errors:
                log.write(
                    f"{module.name}: destinatarios no disponibles "
                    f"({self._recipient_errors[module.name]}); no se podrá ejecutar."
                )
                continue
            for recipient in self._recipients[module.name]:
                log.write(f"{module.name} -> {recipient}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.app.switch_screen(SessionResultScreen(self._session))
            return
        names = set(self.query_one(SelectionList).selected)
        if not names:
            self.notify("Selecciona al menos un módulo.", severity="warning")
            return
        selected = [module for module in self._modules if module.name in names]
        unavailable = [module.name for module in selected if module.name in self._recipient_errors]
        if unavailable:
            self.notify(
                "No se pueden confirmar los destinatarios de: " + ", ".join(unavailable),
                severity="error",
            )
            return
        recipients = {
            module.name: self._recipients[module.name]
            for module in selected
            if getattr(module, "requires_network", False)
        }
        self.app.switch_screen(
            PivotConfirmScreen(self._session, self._choice, selected, recipients)
        )


class PivotConfirmScreen(FlowScreen):
    """Fail-closed consent screen; a checked box is required before the run button enables."""

    def __init__(
        self,
        session: InvestigationSession,
        choice: PivotChoice,
        modules: list[Module],
        recipients: dict[str, tuple[str, ...]],
    ) -> None:
        super().__init__()
        self._session = session
        self._choice = choice
        self._modules = modules
        self._recipients = recipients

    def compose(self) -> ComposeResult:
        value = self._choice.target.to_dict()[self._choice.target_type]
        finding = self._choice.finding
        evidence = safe_evidence_text(finding.detail, self._session.api_key)
        source = safe_evidence_text(finding.source, self._session.api_key)
        source_url = safe_source_url(finding.source_url, self._session.api_key)
        yield Header()
        yield Static(Text(
            f"Destino: {self._choice.target_type}={value}\n"
            f"Origen: {self._choice.parent_entry_id} / {self._choice.source_module} / "
            f"{source}\n"
            f"Valor observado: {finding.value}\n"
            f"Evidencia: {evidence or 'sin detalle adicional'}\n"
            f"URL de fuente: {source_url or 'no disponible'}\n"
            f"Confianza: {finding.confidence:.2f} (no es probabilidad calibrada)\n"
            f"Relación: {EDGE_LABEL}"
        ))
        parent_depth = self._session.entry(self._choice.parent_entry_id).depth
        depth_budget = max(0, self._session.max_depth - parent_depth - 1)
        target_budget = max(0, self._session.remaining_targets - 1)
        yield Static(
            f"Presupuesto tras confirmar: profundidad restante {depth_budget}; "
            f"{target_budget} objetivo(s)."
        )
        yield Label("Módulos y destinatarios")
        yield RichLog(id="confirmation-recipients", markup=False)
        yield Checkbox(
            "Confirmo ejecutar estos módulos y enviar el identificador a los destinatarios "
            "indicados (sin marcar = no ejecutar).",
            id="confirm",
            value=False,
        )
        with Horizontal():
            yield Button("No, cancelar", id="no")
            yield Button("Sí, ejecutar", id="yes", variant="error", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#confirmation-recipients", RichLog)
        for module in self._modules:
            if getattr(module, "requires_network", False):
                for recipient in self._recipients[module.name]:
                    log.write(f"{module.name} -> {recipient}")
            else:
                log.write(f"{module.name}: local; no se envía a terceros.")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "confirm":
            self.query_one("#yes", Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "no":
            self.app.switch_screen(SessionResultScreen(self._session))
            return
        if event.button.id != "yes" or not self.query_one("#confirm", Checkbox).value:
            return
        try:
            entry = self._session.add_pivot(self._choice)
        except (OSError, SessionError) as exc:
            self.notify(
                f"No se pudo iniciar el pivote ({type(exc).__name__}).",
                severity="error",
            )
            return
        self.app.switch_screen(
            RunScreen(
                entry.target,
                self._modules,
                self._session,
                entry.entry_id,
                self.osint_app.output_format,
            )
        )


def _resolve_module_recipients(module: Module) -> tuple[tuple[str, ...], str | None]:
    try:
        return network_recipients(module), None
    except (ModuleSkipped, OSError, ValueError) as exc:
        return (), type(exc).__name__


class DeleteSessionScreen(FlowScreen):
    """Require an explicit, unchecked-by-default confirmation before local deletion."""

    def __init__(self, session: InvestigationSession) -> None:
        super().__init__()
        self._session = session

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            f"Eliminar la sesión local y todos sus informes: {self._session.directory}?"
        )
        yield Checkbox("Confirmo eliminar esta sesión", id="confirm-delete", value=False)
        with Horizontal():
            yield Button("No, conservar", id="no")
            yield Button("Sí, eliminar", id="yes", variant="error", disabled=True)
        yield Footer()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "confirm-delete":
            self.query_one("#yes", Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "no":
            self.app.switch_screen(SessionResultScreen(self._session))
            return
        if event.button.id != "yes" or not self.query_one("#confirm-delete", Checkbox).value:
            return
        try:
            self._session.delete()
        except (OSError, SessionError) as exc:
            self.notify(f"No se pudo eliminar la sesión ({type(exc).__name__}).", severity="error")
            return
        if self.osint_app.current_session is self._session:
            self.osint_app.current_session = None
        self.app.switch_screen(MenuScreen())


class SavedSessionsScreen(FlowScreen):
    """List local sessions so older persisted sessions remain deletable after restart."""

    def __init__(self, output_dir: Path) -> None:
        super().__init__()
        self._output_dir = output_dir
        self._sessions: list[SavedSession] = []
        self._error: str | None = None
        try:
            self._sessions = list_saved_sessions(output_dir)
        except (OSError, SessionError) as exc:
            self._error = type(exc).__name__

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Sesiones guardadas localmente")
        yield Static(
            "Consulta las sesiones guardadas y elimina las que ya no necesites. "
            "Las sesiones no se pueden reanudar.",
            id="history-description",
        )
        if self._error:
            yield Static(f"No se pudieron leer las sesiones ({self._error}).")
        elif self._sessions:
            yield SelectionList[str](
                *(
                    Selection(
                        f"{session.session_id} · {session.created_at} · "
                        f"{session.node_count} nodo(s) · "
                        f"{self._display_status(session)}"
                        + ("" if session.safe_to_delete else " · no eliminable"),
                        session.session_id,
                        False,
                    )
                    for session in self._sessions
                ),
                id="saved-sessions",
            )
        else:
            yield Static("No hay sesiones guardadas.")
        with Horizontal():
            yield Button(
                "Eliminar sesión seleccionada",
                id="delete",
                variant="error",
                disabled=not self._sessions or self._error is not None,
            )
            yield Button("Volver", id="back")
        yield Footer()

    def _display_status(self, session: SavedSession) -> str:
        current = self.osint_app.current_session
        if (
            session.status == EntryStatus.INTERRUPTED.value
            and current is not None
            and current.session_id == session.session_id
            and any(entry.status is EntryStatus.RUNNING for entry in current.entries)
        ):
            return EntryStatus.RUNNING.value
        return session.status

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_menu()
            return
        selected = self.query_one("#saved-sessions", SelectionList).selected
        if len(selected) != 1:
            self.notify("Selecciona exactamente una sesión.", severity="warning")
            return
        session = next(
            (item for item in self._sessions if item.session_id == selected[0]),
            None,
        )
        if session is None or not session.safe_to_delete:
            self.notify("La carpeta no se puede eliminar de forma segura.", severity="error")
            return
        current = self.osint_app.current_session
        if (
            current is not None
            and current.session_id == session.session_id
            and any(entry.status is EntryStatus.RUNNING for entry in current.entries)
        ):
            self.notify(
                "No se puede eliminar una sesión mientras ejecuta una entrada.",
                severity="error",
            )
            return
        self.app.switch_screen(DeleteSavedSessionScreen(self._output_dir, session))


class DeleteSavedSessionScreen(FlowScreen):
    """Confirm deletion of one persisted session, including its per-entry reports."""

    def __init__(self, output_dir: Path, session: SavedSession) -> None:
        super().__init__()
        self._output_dir = output_dir
        self._session = session

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            f"Eliminar la sesión local {self._session.session_id} y sus informes?"
        )
        yield Checkbox("Confirmo eliminar esta sesión", id="confirm-delete", value=False)
        with Horizontal():
            yield Button("No, conservar", id="no")
            yield Button("Sí, eliminar", id="yes", variant="error", disabled=True)
        yield Footer()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "confirm-delete":
            self.query_one("#yes", Button).disabled = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "no":
            self.app.switch_screen(SavedSessionsScreen(self._output_dir))
            return
        if event.button.id != "yes" or not self.query_one("#confirm-delete", Checkbox).value:
            return
        try:
            delete_saved_session(self._output_dir, self._session.session_id)
        except (OSError, SessionError) as exc:
            self.notify(f"No se pudo eliminar la sesión ({type(exc).__name__}).", severity="error")
            return
        if (
            self.osint_app.current_session is not None
            and self.osint_app.current_session.session_id == self._session.session_id
        ):
            self.osint_app.current_session = None
        self.app.switch_screen(SavedSessionsScreen(self._output_dir))


class OsintApp(App[None]):
    TITLE = "OSINTBODY"

    # Mantener el formato en la aplicación permite que la elección persista durante el flujo.
    def __init__(self, output_format: OutputFormat = "all") -> None:
        super().__init__()
        self.output_format = output_format
        self.current_session: InvestigationSession | None = None
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
