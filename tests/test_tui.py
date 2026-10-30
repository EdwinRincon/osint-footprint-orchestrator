import asyncio
import json
from unittest.mock import Mock

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, OptionList, SelectionList, Static

from osint_tool import tui
from osint_tool.config import Settings
from osint_tool.models import (
    Finding,
    ModuleResult,
    Relation,
    Report,
    SourceCheck,
    SourceCheckStatus,
    Status,
    Target,
)
from osint_tool.sessions import InvestigationSession, SessionEdge
from osint_tool.tui import (
    MenuScreen,
    ModuleListScreen,
    ModulesScreen,
    OsintApp,
    PivotConfirmScreen,
    ResultScreen,
    SavedSessionsScreen,
    TargetScreen,
)
from osint_tool.validation import build_target


def test_menu_navega_a_modulos_y_regresa_con_escape() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MenuScreen)
            await pilot.press("down", "enter")
            await pilot.pause()
            assert isinstance(app.screen, ModuleListScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, MenuScreen)

    asyncio.run(scenario())


def test_menu_abre_el_sitio_web(monkeypatch) -> None:
    async def scenario() -> None:
        app = OsintApp()
        open_website = Mock()
        monkeypatch.setattr(app, "open_website", open_website)
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            open_website.assert_called_once_with()

    asyncio.run(scenario())


def test_menu_presenta_historial_local_en_lugar_de_administrar_sesiones() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.pause()
            options = app.screen.query_one(OptionList)
            labels = [
                str(options.get_option_at_index(index).prompt)
                for index in range(options.option_count)
            ]
            assert "Historial local" in labels
            assert "Administrar sesiones locales" not in labels

    asyncio.run(scenario())


def test_historial_local_explica_que_permite_consultar_y_eliminar(tmp_path) -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(SavedSessionsScreen(tmp_path))
            await pilot.pause()
            description = app.screen.query_one("#history-description", Static)
            text = str(description.render()).lower()
            assert "consulta" in text
            assert "elimina" in text

    asyncio.run(scenario())


def test_historial_local_no_muestra_como_interrumpida_la_sesion_activa(tmp_path) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(SavedSessionsScreen(tmp_path))
            await pilot.pause()
            sessions = app.screen.query_one("#saved-sessions", SelectionList)
            item = str(sessions.get_option_at_index(0).prompt).lower()
            assert "running" in item
            assert "interrupted" not in item

    asyncio.run(scenario())


@pytest.mark.parametrize("incompatible_schema", [False, True], ids=["interrupted", "incompatible"])
def test_historial_local_permite_eliminar_sesiones_interrumpidas_y_no_compatibles(
    tmp_path, incompatible_schema: bool
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    if incompatible_schema:
        session_file = session.directory / "session.json"
        data = json.loads(session_file.read_text(encoding="utf-8"))
        data["schema_version"] = "future"
        session_file.write_text(json.dumps(data), encoding="utf-8")

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(SavedSessionsScreen(tmp_path))
            await pilot.pause()
            sessions = app.screen.query_one("#saved-sessions", SelectionList)
            item = str(sessions.get_option_at_index(0).prompt).lower()
            expected_status = (
                "versión no compatible" if incompatible_schema else "interrupted"
            )
            assert expected_status in item
            sessions.select(session.session_id)
            await pilot.click("#delete")
            await pilot.pause()
            assert app.screen.query_one("#confirm-delete", Checkbox)
            await pilot.click("#confirm-delete")
            await pilot.click("#yes")
            await pilot.pause()
            assert not session.directory.exists()
            assert any(
                "no hay sesiones guardadas" in str(widget.render()).lower()
                for widget in app.screen.query(Static)
            )

    asyncio.run(scenario())


def test_open_website_inicia_servidor_y_abre_navegador(
    monkeypatch,
) -> None:
    server = Mock()
    thread = Mock()
    thread_factory = Mock(return_value=thread)
    create_app = Mock(return_value=object())
    make_server = Mock(return_value=server)
    open_browser = Mock(return_value=True)
    monkeypatch.setattr(tui, "create_app", create_app)
    monkeypatch.setattr(tui, "make_server", make_server)
    monkeypatch.setattr(tui, "Thread", thread_factory)
    monkeypatch.setattr(tui.webbrowser, "open", open_browser)

    OsintApp().open_website()

    create_app.assert_called_once_with()
    make_server.assert_called_once_with(
        tui.HOST, tui.PORT, create_app.return_value, threaded=True
    )
    thread_factory.assert_called_once_with(target=server.serve_forever, daemon=True)
    thread.start.assert_called_once_with()
    open_browser.assert_called_once_with(f"http://{tui.HOST}:{tui.PORT}")


def test_formulario_valida_y_avanza_a_modulos() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(TargetScreen())
            await pilot.pause()
            app.screen.query_one("#domain", Input).value = "EJEMPLO.COM"
            app.screen.query_one("#phone", Input).value = "020 7946 0018"
            app.screen.query_one("#phone_region", Input).value = "GB"
            await pilot.click("#next")
            await pilot.pause()
            assert isinstance(app.screen, ModulesScreen)
            assert app.screen._target.phone == "+442079460018"

    asyncio.run(scenario())


def test_modulos_de_red_no_se_seleccionan_automaticamente() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(ModulesScreen(Target(domain="example.test")))
            await pilot.pause()
            assert app.screen.query_one(SelectionList).selected == []

    asyncio.run(scenario())


def test_objetivo_inicial_requiere_consentimiento_y_muestra_destinatario(
    tmp_path, monkeypatch
) -> None:
    target = Target(email="ana@ejemplo.com")
    module = type(
        "NetworkModule",
        (),
        {
            "name": "example",
            "accepts": frozenset({"email"}),
            "requires_network": True,
            "third_party_recipients": ("Example third party",),
        },
    )()
    monkeypatch.setattr(tui, "applicable_modules", lambda *_args, **_kwargs: [module])
    monkeypatch.setattr(tui, "load_settings", lambda: Settings(output_dir=tmp_path))
    run_investigation = Mock(return_value=Report(target=target))
    monkeypatch.setattr(tui, "run_investigation", run_investigation)
    monkeypatch.setattr(
        tui,
        "write_reports",
        Mock(side_effect=lambda _report, directory, _format: (directory, [])),
    )

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(ModulesScreen(target))
            await pilot.pause()
            app.screen.query_one(SelectionList).select("example")
            await pilot.click("#start")
            await pilot.pause()

            assert type(app.screen).__name__ == "InitialConsentScreen"
            assert app.screen.query_one("#confirm", Checkbox).value is False
            assert app.screen.query_one("#yes", Button).disabled
            summary = str(app.screen.query_one("#consent-summary", Static).render())
            recipients = str(app.screen.query_one("#consent-recipients", Static).render())
            assert "ana@ejemplo.com" in summary
            assert "Example third party" in recipients
            run_investigation.assert_not_called()
            assert not (tmp_path / "sessions").exists()

            await pilot.click("#confirm")
            await pilot.click("#yes")
            for _ in range(5):
                await pilot.pause()
                if type(app.screen).__name__ == "SessionResultScreen":
                    break
            assert type(app.screen).__name__ == "SessionResultScreen"
            run_investigation.assert_called_once()
            assert (tmp_path / "sessions").exists()

    asyncio.run(scenario())


def test_modulo_hibp_muestra_aviso_de_divulgacion_y_requisito() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(ModulesScreen(Target(email="ana@ejemplo.com")))
            await pilot.pause()
            notices = [str(widget.render()) for widget in app.screen.query(Static)]
            assert any("Have I Been Pwned" in notice for notice in notices)
            assert any("un tercero" in notice for notice in notices)
            assert any("OSINT_HIBP_API_KEY" in notice for notice in notices)

    asyncio.run(scenario())


def test_dato_invalido_se_queda_en_el_formulario() -> None:
    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app.switch_screen(TargetScreen())
            await pilot.pause()
            app.screen.query_one("#domain", Input).value = "no es un dominio"
            await pilot.click("#next")
            await pilot.pause()
            assert isinstance(app.screen, TargetScreen)
            assert "dominio no válido" in str(app.screen.query_one("#error", Static).render())

    asyncio.run(scenario())


def test_resultados_muestran_hallazgos_y_relaciones_en_terminal(tmp_path) -> None:
    finding = Finding(
        entity_type="username",
        type="profile",
        value="https://example.test/demo_user",
        source="Sitio ficticio",
        detail="Perfil observado",
        confidence=0.5,
    )
    relation = Relation(
        "username:demo_user",
        "profile:https://example.test/demo_user",
        "perfil observado",
        0.5,
        ("Sitio ficticio",),
    )
    report = Report(
        target=Target(username="demo_user"),
        results=[ModuleResult("usernames", Status.OK, [finding])],
        relations=[relation],
    )

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(120, 40)) as pilot:
            app.switch_screen(ResultScreen(report, tmp_path, []))
            await pilot.pause()

            findings = app.screen.query_one("#findings", DataTable)
            relations = app.screen.query_one("#relations", DataTable)
            assert findings.row_count == 1
            assert relations.row_count == 1
            assert "https://example.test/demo_user" in str(findings.get_row_at(0))
            assert "Sitio ficticio" in str(relations.get_row_at(0))

    asyncio.run(scenario())


def test_resultados_muestran_fuentes_no_configuradas_en_terminal(tmp_path) -> None:
    report = Report(
        target=Target(email="ana@ejemplo.com"),
        results=[
            ModuleResult(
                "hibp",
                Status.OK,
                source_checks=[
                    SourceCheck("Have I Been Pwned", SourceCheckStatus.NOT_CONFIGURED)
                ],
            )
        ],
    )

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(120, 40)) as pilot:
            app.switch_screen(ResultScreen(report, tmp_path, []))
            await pilot.pause()
            modules = app.screen.query_one("#modules", DataTable)
            assert "Have I Been Pwned: not_configured" in str(modules.get_row_at(0))

    asyncio.run(scenario())


def test_resultados_de_sesion_sanean_hallazgos_y_aristas_en_terminal(tmp_path) -> None:
    api_key = "session-secret-739"
    session = InvestigationSession.create(
        tmp_path,
        build_target(username="root"),
        api_key=api_key,
    )
    finding = Finding(
        entity_type="username",
        type="profile",
        value=f"account-{api_key}",
        source="Example",
        detail=f"key={api_key}; request https://api.example.test/lookup?token={api_key}",
        source_url=f"https://api.example.test/lookup?token={api_key}",
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(username="root"),
            results=[ModuleResult("profiles", Status.OK, [finding])],
        ),
    )
    session.edges.append(
        SessionEdge(
            parent_entry_id="entry-1",
            child_entry_id="entry-2",
            source_module="profiles",
            source_url=f"https://api.example.test/source?token={api_key}",
            evidence_text=f"Bearer {api_key} https://api.example.test/request?token={api_key}",
            confidence=0.5,
        )
    )

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(tui.SessionResultScreen(session))
            await pilot.pause()
            finding_row = str(app.screen.query_one("#session-findings", DataTable).get_row_at(0))
            edge_row = str(app.screen.query_one("#session-edges", DataTable).get_row_at(0))
            assert api_key not in finding_row
            assert "api.example.test" not in finding_row
            assert api_key not in edge_row
            assert "api.example.test" not in edge_row

    asyncio.run(scenario())


def test_confirmacion_de_pivot_empieza_en_no_y_rechazar_no_ejecuta(
    tmp_path, monkeypatch
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    finding = Finding(
        entity_type="username",
        type="profile",
        value="alice",
        source="Example site",
        source_url="https://example.test/root",
        detail="Username observed",
        confidence=0.5,
    )
    report = Report(
        target=build_target(username="root"),
        results=[ModuleResult("profiles", Status.OK, [finding])],
    )
    session.complete_entry("entry-1", report)
    choice = next(
        choice
        for choice in session.pivot_choices()
        if choice.target_type == "username"
    )
    module = type(
        "NetworkModule",
        (),
        {"name": "example", "accepts": frozenset({"username"}), "requires_network": True},
    )()
    run_investigation = Mock()
    monkeypatch.setattr(tui, "run_investigation", run_investigation)

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(
                PivotConfirmScreen(
                    session,
                    choice,
                    [module],
                    {"example": ("Example third party",)},
                )
            )
            await pilot.pause()
            assert app.screen.query_one("#confirm", Checkbox).value is False
            assert app.screen.query_one("#yes", Button).disabled
            run_investigation.assert_not_called()

            await pilot.click("#no")
            await pilot.pause()
            assert isinstance(app.screen, tui.SessionResultScreen)
            run_investigation.assert_not_called()

    asyncio.run(scenario())


def test_confirmacion_de_pivot_muestra_el_valor_declarado(tmp_path) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    finding = Finding(
        entity_type="username",
        type="profile",
        value="https://github.com/ana",
        source="GitHub",
        raw={
            "pivots": [
                {"kind": "email", "value": "ana@ejemplo.com", "explicit": True}
            ]
        },
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(username="root"),
            results=[ModuleResult("github_profile", Status.OK, [finding])],
        ),
    )
    choice = next(choice for choice in session.pivot_choices() if choice.target_type == "email")

    async def scenario() -> None:
        app = OsintApp()
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(PivotConfirmScreen(session, choice, [], {}))
            await pilot.pause()
            text = " ".join(str(widget.render()) for widget in app.screen.query(Static))
            assert "Valor observado: ana@ejemplo.com" in text

    asyncio.run(scenario())


def test_pivot_selector_no_ejecuta_modulos_automaticamente(
    tmp_path, monkeypatch
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    finding = Finding(
        entity_type="username",
        type="profile",
        value="alice",
        source="Example site",
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(username="root"),
            results=[ModuleResult("profiles", Status.OK, [finding])],
        ),
    )
    choice = next(
        choice
        for choice in session.pivot_choices()
        if choice.target_type == "username"
    )
    monkeypatch.setattr(tui, "network_recipients", lambda _module: ("Example provider",))
    run_investigation = Mock()
    monkeypatch.setattr(tui, "run_investigation", run_investigation)

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(tui.PivotModulesScreen(session, choice))
            await pilot.pause()
            assert app.screen.query_one(SelectionList).selected == []
            assert app.screen.query_one("#review", Button).disabled is False
            run_investigation.assert_not_called()

    asyncio.run(scenario())


def test_pivot_ambiguo_no_elige_tipo_por_defecto(tmp_path) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    finding = Finding(
        entity_type="username",
        type="profile",
        value="alice",
        source="Example site",
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(username="root"),
            results=[ModuleResult("profiles", Status.OK, [finding])],
        ),
    )
    assert {
        choice.target_type for choice in session.pivot_choices()
    } == {"username", "name"}

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(tui.PivotSelectionScreen(session))
            await pilot.pause()
            selection = app.screen.query_one("#pivot-choices", SelectionList)
            assert selection.selected == []
            await pilot.click("#select")
            await pilot.pause()
            assert isinstance(app.screen, tui.PivotSelectionScreen)

    asyncio.run(scenario())


def test_confirmacion_explicita_inicia_el_nuevo_nodo(tmp_path, monkeypatch) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    finding = Finding(
        entity_type="username",
        type="profile",
        value="alice",
        source="Example site",
    )
    session.complete_entry(
        "entry-1",
        Report(
            target=build_target(username="root"),
            results=[ModuleResult("profiles", Status.OK, [finding])],
        ),
    )
    choice = next(
        choice
        for choice in session.pivot_choices()
        if choice.target_type == "username"
    )
    module = type(
        "LocalModule",
        (),
        {"name": "local", "accepts": frozenset({"username"}), "requires_network": False},
    )()
    report = Report(target=choice.target)
    run_investigation = Mock(return_value=report)
    report_path = session.directory / "reports" / "entry-2" / "20260101T000000-abcdef"
    monkeypatch.setattr(tui, "run_investigation", run_investigation)
    monkeypatch.setattr(tui, "write_reports", Mock(return_value=(report_path, [])))

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(
                PivotConfirmScreen(session, choice, [module], {})
            )
            await pilot.pause()
            assert app.screen.query_one("#yes", Button).disabled
            await pilot.click("#confirm")
            await pilot.pause()
            assert not app.screen.query_one("#yes", Button).disabled
            await pilot.click("#yes")
            for _ in range(5):
                await pilot.pause()
                if isinstance(app.screen, tui.SessionResultScreen):
                    break
            assert isinstance(app.screen, tui.SessionResultScreen)
            run_investigation.assert_called_once()
            assert session.entries[1].status.value == "completed"

    asyncio.run(scenario())


def test_error_de_entrada_marca_nodo_fallido_y_conserva_sesion(
    tmp_path, monkeypatch
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    run_investigation = Mock(side_effect=RuntimeError("https://api.example.test/request"))
    monkeypatch.setattr(tui, "run_investigation", run_investigation)

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(
                tui.RunScreen(
                    session.entries[0].target,
                    [],
                    session,
                    "entry-1",
                    "json",
                )
            )
            for _ in range(5):
                await pilot.pause()
                if isinstance(app.screen, tui.SessionResultScreen):
                    break
            assert isinstance(app.screen, tui.SessionResultScreen)
            assert session.entries[0].status.value == "failed"
            run_investigation.assert_called_once()

    asyncio.run(scenario())


def test_fallo_del_reporter_persiste_entrada_fallida_en_vez_de_running(
    tmp_path, monkeypatch
) -> None:
    session = InvestigationSession.create(tmp_path, build_target(username="root"))
    report = Report(target=session.entries[0].target)
    run_investigation = Mock(return_value=report)
    write_reports = Mock(side_effect=OSError("disk full"))
    monkeypatch.setattr(tui, "run_investigation", run_investigation)
    monkeypatch.setattr(tui, "write_reports", write_reports)

    async def scenario() -> None:
        app = OsintApp()
        app.current_session = session
        async with app.run_test(size=(120, 45)) as pilot:
            app.switch_screen(
                tui.RunScreen(
                    session.entries[0].target,
                    [],
                    session,
                    "entry-1",
                    "json",
                )
            )
            for _ in range(5):
                await pilot.pause()
                if isinstance(app.screen, tui.SessionResultScreen):
                    break
            assert isinstance(app.screen, tui.SessionResultScreen)
            assert session.entries[0].status.value == "failed"
            stored = json.loads((session.directory / "session.json").read_text(encoding="utf-8"))
            assert stored["nodes"][0]["status"] == "failed"
            run_investigation.assert_called_once()
            write_reports.assert_called_once()

    asyncio.run(scenario())
