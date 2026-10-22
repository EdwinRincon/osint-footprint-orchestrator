from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver
from whois.exceptions import WhoisError

from osint_tool.models import Target
from osint_tool.modules.domain import DomainModule


class FakeRdata:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class FakeResolver:
    def __init__(self, data: dict[str, list[str]] | None = None, error: Exception | None = None):
        self.data = data or {}
        self.error = error

    def resolve(self, name: str, rtype: str) -> list[FakeRdata]:
        if self.error:
            raise self.error
        if rtype not in self.data:
            raise dns.resolver.NoAnswer()
        return [FakeRdata(t) for t in self.data[rtype]]


def _whois(data: dict[str, Any]):  # type: ignore[no-untyped-def]
    return lambda domain: data


TARGET = Target(domain="ejemplo.com")


def test_registros_dns() -> None:
    resolver = FakeResolver({"A": ["93.184.216.34"], "MX": ["10 mail.ejemplo.com."]})
    findings = DomainModule(resolver, _whois({})).run(TARGET)
    assert [f.value for f in findings] == ["A 93.184.216.34", "MX 10 mail.ejemplo.com."]
    assert all(f.source == "DNS" and f.type == "dns_record" for f in findings)


def test_campos_whois() -> None:
    data = {
        "registrar": "Registrador SA",
        "org": "Ejemplo SL",
        "creation_date": [
            datetime(2000, 1, 1, tzinfo=timezone.utc),
            datetime(2000, 1, 2, tzinfo=timezone.utc),
        ],
        "expiration_date": datetime(2030, 5, 6, tzinfo=timezone.utc),
        "emails": ["admin@ejemplo.com", "Select Request Email Form"],
    }
    findings = DomainModule(FakeResolver(), _whois(data)).run(TARGET)
    by_type = {f.type: f for f in findings}
    assert by_type["whois_registrar"].value == "Registrador SA"
    assert by_type["whois_created"].value == "2000-01-01"
    assert by_type["whois_expires"].value == "2030-05-06"
    contacts = [f for f in findings if f.type == "whois_contact"]
    assert [c.value for c in contacts] == ["admin@ejemplo.com"]
    assert contacts[0].entity_type == "email" and contacts[0].confidence < 1.0


def test_dominio_inexistente_no_falla() -> None:
    resolver = FakeResolver(error=dns.resolver.NXDOMAIN())
    findings = DomainModule(resolver, _whois({"registrar": "X"})).run(TARGET)
    assert [f.type for f in findings] == ["whois_registrar"]


def test_timeout_dns_no_falla() -> None:
    resolver = FakeResolver(error=dns.exception.Timeout())
    assert DomainModule(resolver, _whois({})).run(TARGET) == []


def test_error_whois_conserva_dns() -> None:
    def roto(domain: str) -> dict[str, Any]:
        raise WhoisError("caido")

    findings = DomainModule(FakeResolver({"A": ["1.2.3.4"]}), roto).run(TARGET)
    assert [f.value for f in findings] == ["A 1.2.3.4"]


def test_sin_dominio_devuelve_vacio() -> None:
    assert DomainModule(FakeResolver(), _whois({})).run(Target(email="a@ejemplo.com")) == []
