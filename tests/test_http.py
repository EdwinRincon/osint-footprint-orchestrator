import pytest
import requests

from osint_tool.config import Settings
from osint_tool.http import build_session


def test_user_agent_y_reintentos() -> None:
    s = build_session(Settings(http_retries=2, user_agent="test-agent"))
    assert s.headers["User-Agent"] == "test-agent"
    assert s.get_adapter("https://ejemplo.com").max_retries.total == 2


def test_timeout_por_defecto(monkeypatch: pytest.MonkeyPatch) -> None:
    capturado: dict = {}

    def falso(self, method, url, **kwargs):  # type: ignore[no-untyped-def]
        capturado.update(kwargs)
        return requests.Response()

    monkeypatch.setattr(requests.Session, "request", falso)
    build_session(Settings(http_timeout=7)).get("https://ejemplo.com")
    assert capturado["timeout"] == 7


def test_timeout_explicito_prevalece(monkeypatch: pytest.MonkeyPatch) -> None:
    capturado: dict = {}

    def falso(self, method, url, **kwargs):  # type: ignore[no-untyped-def]
        capturado.update(kwargs)
        return requests.Response()

    monkeypatch.setattr(requests.Session, "request", falso)
    build_session(Settings(http_timeout=7)).get("https://ejemplo.com", timeout=3)
    assert capturado["timeout"] == 3