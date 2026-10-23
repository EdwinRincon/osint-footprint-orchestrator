from types import SimpleNamespace

import pytest

from osint_tool import __version__, cli


def test_terminal_interactivo_inicia_textual(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(cli.sys, "stdout", SimpleNamespace(isatty=lambda: True))
    calls: list[bool] = []
    monkeypatch.setattr(cli, "run_tui", lambda: calls.append(True))

    assert cli.main([]) == 0
    assert calls == [True]


def test_sin_tty_no_intenta_iniciar_interfaz(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(cli.sys, "stdout", SimpleNamespace(isatty=lambda: False))

    assert cli.main([]) == 2
    assert "requiere una terminal" in capsys.readouterr().err


def test_version_sigue_disponible(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert f"osint {__version__}" in capsys.readouterr().out


def test_help_documenta_solo_el_flujo_interactivo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "--version" in output
    assert "--domain" not in output
    assert "--list-modules" not in output


@pytest.mark.parametrize(
    "arguments",
    [
        ["--domain", "ejemplo.com"],
        ["--email", "ana@ejemplo.com", "--format", "html"],
        ["--list-modules"],
    ],
)
def test_opciones_del_flujo_antiguo_se_rechazan(arguments: list[str]) -> None:
    assert cli.main(arguments) == 2
