import asyncio
from unittest.mock import Mock

from textual.widgets import DataTable, Input, Static

from osint_tool import tui
from osint_tool.models import Finding, ModuleResult, Relation, Report, Status, Target
from osint_tool.tui import (
    MenuScreen,
    ModuleListScreen,
    ModulesScreen,
    OsintApp,
    ResultScreen,
    TargetScreen,
)


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
            await pilot.click("#next")
            await pilot.pause()
            assert isinstance(app.screen, ModulesScreen)

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
