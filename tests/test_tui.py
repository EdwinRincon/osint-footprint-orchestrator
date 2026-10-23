import asyncio

from textual.widgets import Input, Static

from osint_tool.tui import (
    MenuScreen,
    ModuleListScreen,
    ModulesScreen,
    OsintApp,
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
