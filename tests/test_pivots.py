from typing import Any

import pytest

from osint_tool.pivots import (
    Pivot,
    build_account_index,
    canonical_account,
    extract_github,
    normalize_website,
)

SITES = [
    ("Reddit", "https://www.reddit.com/user/{username}"),
    ("Reddit Old", "https://old.reddit.com/{username}"),
    ("Foo", "https://foo.com/{username}"),
    ("Foo Pro", "https://foo.com/pro/{username}"),
    ("Medio", "https://medio.com/{username}/posts"),
    ("Subdominio", "https://{username}.blog.com"),
    ("X", "https://x.com/{username}"),
]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://www.reddit.com/user/Ana", "reddit:ana"),
        ("reddit.com/user/ana/", "reddit:ana"),
        ("https://x.com/Ana", "twitter:ana"),  # el alias manual gana al dataset
        ("https://github.com/Ana", "github:ana"),
        ("https://medio.com/ana/posts", None),  # cuenta no es el último segmento
        ("https://ana.blog.com", None),
        ("https://reddit.com/user", None),
    ],
)
def test_canonical_account_con_indice(value: str, expected: str | None) -> None:
    assert canonical_account(value, index=build_account_index(SITES)) == expected


def test_prefijo_mas_largo_gana() -> None:
    index = build_account_index(SITES)
    assert canonical_account("https://foo.com/pro/ana", index=index) == "foo-pro:ana"
    assert canonical_account("https://foo.com/ana", index=index) == "foo:ana"


def test_sin_indice_reddit_no_se_reconoce() -> None:
    assert canonical_account("https://reddit.com/user/ana") is None


def test_extract_github_reconoce_blog_de_reddit() -> None:
    index = build_account_index(SITES)
    pivots = extract_github({"blog": "https://reddit.com/user/Ana"}, index)
    assert pivots == [Pivot("account", "reddit:ana", explicit=True)]


@pytest.mark.parametrize(
    ("value", "platform", "expected"),
    [
        ("https://twitter.com/Ana", None, "twitter:ana"),
        ("https://x.com/ana/", None, "twitter:ana"),
        ("http://www.X.com/ana?lang=es", None, "twitter:ana"),
        ("twitter.com/ana", None, "twitter:ana"),
        ("@Ana", "twitter", "twitter:ana"),
        ("ana", "github", "github:ana"),
        ("https://github.com/ana/repo", None, "github:ana"),
        ("@ana", None, None),
        ("@ana", "desconocida", None),
        ("https://example.com/ana", None, None),
        ("https://x.com/", None, None),
        ("https://x.com/home", None, None),
        ("https://user:pw@x.com/ana", None, None),
        ("ftp://x.com/ana", None, None),
        ("javascript:alert(1)", "twitter", None),
        ("", "twitter", None),
        ("@", "twitter", None),
        ("a b", "twitter", None),
    ],
)
def test_canonical_account(value: str, platform: str | None, expected: str | None) -> None:
    assert canonical_account(value, platform) == expected


def test_alias_de_twitter_y_x_dan_la_misma_clave() -> None:
    assert canonical_account("https://twitter.com/ana") == canonical_account("https://x.com/ANA")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ana.dev", "https://ana.dev"),
        ("https://www.Ana.dev/", "https://ana.dev"),
        ("http://ana.dev/blog/", "http://ana.dev/blog"),
        ("https://ana.dev/a?x=1#f", "https://ana.dev/a"),
        ("https://ana.dev:8443/", "https://ana.dev:8443"),
        ("  ", None),
        ("", None),
        ("javascript:alert(1)", None),
        ("data:text/html,hola", None),
        ("ftp://ana.dev", None),
        ("https://user:pw@ana.dev", None),
        ("https://localhost", None),
        ("https://127.0.0.1", None),
        ("https://ana .dev", None),
        ("https://ana.dev:abc", None),
    ],
)
def test_normalize_website(value: str, expected: str | None) -> None:
    assert normalize_website(value) == expected


def test_normalize_website_es_idempotente() -> None:
    once = normalize_website("WWW.Ana.dev/blog/")
    assert once is not None
    assert normalize_website(once) == once


def test_extrae_los_pivotes_declarados_de_github() -> None:
    payload = {
        "login": "ana",
        "blog": "https://www.ana.dev/",
        "twitter_username": "AnaDev",
        "email": "Ana@Ejemplo.com",
        "gravatar_id": "A" * 32,
        "location": "Madrid",
        "company": "@acme",
    }

    assert extract_github(payload) == [
        Pivot("website", "https://ana.dev", explicit=True),
        Pivot("account", "twitter:anadev", explicit=True),
        Pivot("email", "ana@ejemplo.com", explicit=True),
        Pivot("gravatar", "a" * 32, explicit=False),
    ]


def test_ubicacion_y_empresa_no_son_pivotes() -> None:
    assert extract_github({"location": "Madrid", "company": "@acme", "bio": "hola"}) == []


def test_un_blog_que_es_una_cuenta_conocida_se_trata_como_cuenta() -> None:
    assert extract_github({"blog": "https://x.com/ana"}) == [
        Pivot("account", "twitter:ana", explicit=True)
    ]


def test_no_duplica_pivotes_equivalentes() -> None:
    payload = {"blog": "https://twitter.com/ana", "twitter_username": "ANA"}
    assert extract_github(payload) == [Pivot("account", "twitter:ana", explicit=True)]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"blog": None, "twitter_username": None, "email": None, "gravatar_id": None},
        {"blog": 5, "twitter_username": ["x"], "email": {}, "gravatar_id": 1},
        {"blog": "javascript:alert(1)", "email": "no-es-email", "gravatar_id": "zz"},
        {"blog": "", "twitter_username": "  ", "email": "", "gravatar_id": ""},
    ],
)
def test_ignora_campos_vacios_nulos_o_mal_tipados(payload: dict[str, Any]) -> None:
    assert extract_github(payload) == []


def test_pivot_se_serializa_y_se_reconstruye() -> None:
    pivot = Pivot("email", "ana@ejemplo.com", explicit=True)
    assert Pivot.from_dict(pivot.to_dict()) == pivot


@pytest.mark.parametrize(
    "data",
    [
        None,
        "texto",
        {},
        {"kind": "desconocido", "value": "x", "explicit": True},
        {"kind": "email", "value": "", "explicit": True},
        {"kind": "email", "value": 3, "explicit": True},
        {"kind": "email", "value": "a@b.co", "explicit": "si"},
    ],
)
def test_pivot_from_dict_rechaza_datos_invalidos(data: Any) -> None:
    assert Pivot.from_dict(data) is None
