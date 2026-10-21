import sys

import pytest

from osint_tool.cli_runner import CliError, ToolNotFoundError, run_cli


def test_ejecuta_comando() -> None:
    r = run_cli([sys.executable, "-c", "print('hola')"])
    assert r.returncode == 0
    assert r.stdout.strip() == "hola"


def test_codigo_de_salida_no_lanza_error() -> None:
    r = run_cli([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert r.returncode == 3


def test_no_interpreta_metacaracteres() -> None:
    r = run_cli([sys.executable, "-c", "import sys; print(sys.argv[1])", "a; echo hacked"])
    assert r.stdout.strip() == "a; echo hacked"


def test_rechaza_string() -> None:
    with pytest.raises(TypeError):
        run_cli("echo hola")  # type: ignore[arg-type]


def test_herramienta_inexistente() -> None:
    with pytest.raises(ToolNotFoundError):
        run_cli(["herramienta-que-no-existe-xyz"])


def test_timeout() -> None:
    with pytest.raises(CliError):
        run_cli([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)