# OSINT Tool

Herramienta en Python que recopila información **pública** a partir de un email, username, dominio, teléfono o nombre. Correlaciona los resultados, genera un informe (JSON y HTML), un grafo con Graphviz y ofrece una web básica.

> ⚠️ **Uso responsable:** solo con fines educativos, con datos propios o ficticios, y respetando los términos de servicio de cada fuente y el RGPD. Cada informe incluye este aviso.

## Requisitos

- Python 3.10+
- [Graphviz](https://graphviz.org/download/) (comando `dot` en el PATH)
- Opcional: [theHarvester](https://github.com/laramies/theHarvester). Si no está instalado, su módulo se marca como `skipped`.

No se necesitan claves de API. El módulo de brechas usa la API pública de [XposedOrNot](https://xposedornot.com/api_doc), con límite de uso por IP (25 consultas por hora y 100 por día). Si se supera, el módulo se marca como `skipped`.

## Instalación

```bash
python -m venv .venv

# Activar el entorno
source .venv/bin/activate        # Linux/macOS
source .venv/Scripts/activate    # Windows (Git Bash)
.venv\Scripts\activate           # Windows (CMD)

pip install -e ".[dev]"          # instala el paquete y ruff, mypy, pytest
```

## Estructura

```text
osint-tool/
├── pyproject.toml           # dependencias, entry point y config de ruff/mypy/pytest
├── src/osint_tool/
│   ├── __init__.py          # versión del paquete
│   ├── py.typed             # marca el paquete como tipado (PEP 561)
│   ├── config.py            # lee el entorno: timeouts y carpeta de salida
│   ├── models.py            # Target, Finding, ModuleResult, Relation, Report
│   ├── validation.py        # listas blancas (regex); normaliza y construye Target
│   ├── http.py              # requests.Session compartida (User-Agent, timeout, reintentos)
│   ├── cli_runner.py        # run_cli(): subprocess con shell=False y timeout
│   ├── registry.py          # protocolo Module, @register y ModuleSkipped
│   ├── service.py           # run_investigation(target, modules) -> Report
│   ├── correlator.py        # relaciona hallazgos y asigna confianza
│   ├── modules/
│   │   ├── __init__.py      # autodescubrimiento de módulos
│   │   ├── breaches.py      # brechas de datos con XposedOrNot (email)
│   │   ├── usernames.py     # username en varias redes
│   │   ├── domain.py        # WHOIS + DNS (dominio)
│   │   ├── phone.py         # país, operador y tipo de línea (phonenumbers)
│   │   └── harvester.py     # ejecuta theHarvester y parsea su JSON
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── base.py          # interfaz Reporter
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   └── graph.py         # genera .dot y .png con Graphviz
│   ├── cli.py               # argumentos de línea de comandos
│   └── web/
│       ├── __init__.py
│       ├── app.py           # Flask (solo localhost)
│       └── templates/index.html
├── tests/                   # un test por módulo, correlator y validación
├── .gitignore               # reports/, .venv/, .env
└── reports/                 # salida: reports/<timestamp>/
```

## Uso

### Línea de comandos

```bash
osint --email test@example.com
osint --username usuario_demo
osint --domain ejemplo.com
osint --phone +34600000000
osint --name "Ana Pérez" --username anaperez --domain ejemplo.com
osint --email test@example.com --modules breaches,domain --format json
```

Opciones:

- `--modules a,b`: ejecuta solo esos módulos (por defecto, todos los aplicables).
- `--format json|html|all`: formato del informe (por defecto, `all`). `html` y `all` incluyen también el grafo.
- `--list-modules`: muestra los módulos registrados y las entradas que aceptan.
- `-v, --verbose`: muestra mensajes informativos (por ejemplo, redes que bloquean la comprobación).

Combina varios datos para que la correlación enlace resultados.

### Interfaz web

```bash
python -m osint_tool.web.app     # abre http://127.0.0.1:5000
```

Rellena al menos un campo y pulsa **Iniciar búsqueda**. Los módulos habituales se seleccionan según los datos; las herramientas externas opcionales, como theHarvester, aparecen desmarcadas y solo se ejecutan si las activas. La página muestra el informe y el grafo. Cada búsqueda se guarda en su propia carpeta, así que dos peticiones simultáneas no se pisan.

### Salida

Cada ejecución crea `reports/<timestamp>/`:

- `report.json`: datos completos, con el estado de cada módulo.
- `report.html`: informe legible, con el aviso RGPD.
- `graph.dot` y `graph.png`: grafo de relaciones.

## Arquitectura

CLI y web son capas finas. Ambas llaman a una única función, sin duplicar lógica:

```text
validation → Target → service.run_investigation() → módulos → correlator → Report → reporters
```

### Modelos (`models.py`)

- `Target`: dataclass inmutable con `email`, `username`, `domain`, `phone`, `name` (todos opcionales, al menos uno). El formato lo valida `validation.py` antes de construirlo.
- `Finding`: `entity_type`, `type`, `value`, `source`, `confidence` (heurística 0–1), `raw` (dato original, opcional) y `retrieved_at` (UTC, automático).
- `Finding.source_url`: referencia web de la fuente cuando se conoce; no se incluye la URL de consulta del email a brechas para evitar volver a exponerlo en enlaces.
- `ModuleOutput`: `findings` y `source_checks` (comprobaciones por fuente; compatible con módulos que devuelven solo una lista de hallazgos).
- `SourceCheck`: fuente, estado (`found`, `not_found`, `inconclusive` o `error`), detalle técnico no sensible y hora de consulta.
- `ModuleResult`: `name`, `status` (`ok` | `skipped` | `error`), `findings`, `error`, `duration`.
- `Relation`: `source`, `target`, `label`, `confidence`. Es una hipótesis del correlador.
- `Report`: `target`, `results`, `relations`, `created_at`. `to_dict()` lo serializa a JSON.

### Validación (`validation.py`)

Todo dato pasa por listas blancas (regex) y se normaliza: email y dominio en minúsculas, teléfono en formato E.164 (`+34600000000`) y espacios repetidos colapsados en el nombre. Los errores no repiten el valor recibido, para no volcar datos personales en logs.

### Configuración (`config.py`)

Es el único archivo que lee el entorno. Todas las variables son opcionales:

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `OSINT_HTTP_TIMEOUT` | `10` | Segundos por petición HTTP |
| `OSINT_HTTP_RETRIES` | `2` | Reintentos ante errores 5xx |
| `OSINT_CLI_TIMEOUT` | `60` | Segundos para herramientas externas |
| `OSINT_OUTPUT_DIR` | `reports` | Carpeta de salida |

### Contrato de módulo

```python
# src/osint_tool/modules/mi_modulo.py
from osint_tool.models import Finding, Target
from osint_tool.registry import register


@register
class MiModulo:
    name = "mi_modulo"
    accepts = frozenset({"email"})   # email, username, domain, phone, name

    def run(self, target: Target) -> list[Finding]:
        """Consulta una fuente y devuelve hallazgos en el formato común."""
        return [Finding(entity_type="email", type="breach",
                        value="Ejemplo", source="Fuente", confidence=1.0)]
```

`service.py` ejecuta en serie solo los módulos cuyo `accepts` coincide con los datos del `Target`. Cada módulo se envuelve en un `ModuleResult`:

- `ok`: el módulo terminó, con o sin hallazgos.
- `skipped`: el módulo lanzó `ModuleSkipped` (límite de uso alcanzado) o la herramienta externa no está instalada.
- `error`: fallo de red, de parseo o del comando. Se registra con `logging` y los demás módulos continúan.

### Añadir o integrar fuentes

1. Crea el archivo en `modules/` con el decorador `@register`. No hay que editar ninguna lista.
2. **Herramientas CLI** (theHarvester, Recon-ng...): usa `run_cli([...])` y convierte la salida a `Finding`. `harvester.py` lanza `theHarvester -d <dominio> -b crtsh -f <nombre>` y lee `<nombre>.json`; si falta, lo tolera. Para que la web la muestre como opción explícita y no la ejecute por defecto, declara `web_opt_in = True` en la clase del módulo y, opcionalmente, `web_label = "Nombre visible"`.
3. **APIs o scripts propios:** usa la sesión de `http.py` (ya trae `timeout` y reintentos limitados) o lánzalos con `run_cli`.
4. Añade un test en `tests/` con la red y el ejecutor simulados.

### Correlación

`correlator.py` genera relaciones entre entidades y les asigna una puntuación heurística `confidence`:

- Mismo username en varias redes.
- Dominio del email igual al dominio analizado.
- Los campos aportados junto con un nombre no se conectan entre sí: la coincidencia de entradas no prueba identidad.
- Un email y un dominio aportados se conectan solo cuando el dominio coincide textualmente; esto no verifica titularidad.

Si varias fuentes apoyan una relación, se conserva la puntuación más alta, sin suponer que las fuentes sean estadísticamente independientes. La puntuación no es una probabilidad. Las relaciones de confianza baja aparecen con trazo discontinuo en el grafo.

## Calidad

```bash
ruff check .    # estilo y errores comunes
mypy src        # tipos (modo estricto)
pytest          # tests sin red
```

Los módulos reciben la sesión HTTP y el ejecutor CLI por parámetro, así que los tests usan mocks y no necesitan red.

## Seguridad y privacidad

- Solo fuentes públicas o APIs oficiales; sin evadir bloqueos.
- Algunos módulos envían el dato consultado a servicios de terceros (el email a XposedOrNot, el username a las redes comprobadas). Usa solo datos propios o ficticios.
- `run_cli` recibe una **lista** (nunca un string), usa `shell=False` y `timeout`. Las entradas se validan antes de usarlas en comandos, DNS o URLs.
- La configuración se lee solo en `config.py`; si se añade una fuente con clave, debe leerse del entorno y nunca escribirse en el código.
- La web escucha solo en `127.0.0.1`, sin autenticación: no la expongas a internet. Usa `debug=False` y el escapado automático de Jinja2 (sin `|safe` con datos externos).
- Los informes se guardan en `reports/` (o en `OSINT_OUTPUT_DIR`) y persisten hasta que los elimines manualmente. Pueden contener datos personales: protege esa carpeta y elimina los informes cuando dejen de ser necesarios.

## Cumplimiento del enunciado

| Requisito | Cómo se cumple | Test |
| --- | --- | --- |
| Entrada por nombre, email, username, teléfono o dominio | `cli.py` y formulario web; validado en `validation.py` | `test_validation.py` |
| Mínimo 3 fuentes | `breaches.py`, `usernames.py`, `domain.py` (+ `phone.py`) | `test_breaches.py`, `test_usernames.py`, `test_domain.py`, `test_phone.py` |
| Herramienta externa | `harvester.py` con `run_cli` y parseo de JSON | `test_harvester.py` |
| Modular e integrable | Protocolo `Module`, `@register`, `run_cli()` | `test_registry.py` |
| Informe estructurado | `json_reporter.py` y `html_reporter.py` | `test_reporters.py` |
| Código modular y comentado | Un archivo por responsabilidad, con docstrings y tipos | `ruff` y `mypy` |
| Correlación | `correlator.py` con niveles de confianza | `test_correlator.py` |
| Grafo de relaciones | `graph.dot` y `graph.png` con Graphviz | `test_graph.py` |
| Interfaz web | `web/app.py` con Flask | `test_web.py` |

## Decisiones de diseño

Se evitó añadir complejidad que una herramienta local no necesita:

- Sin base de datos, colas, async ni Docker.
- Sin sistema de plugins externo: basta con `@register`.
- Ejecución en serie. Si hace falta velocidad, se puede usar `ThreadPoolExecutor` en `service.py`, porque `ModuleResult` ya aísla cada módulo.

## Limitaciones

- Las correlaciones son hipótesis y deben verificarse manualmente.
- Que un username exista en varias redes no prueba que pertenezca a la misma persona.
- El informe distingue comprobaciones de username encontradas, no encontradas, inconclusas y con error; los bloqueos no se cuentan como "no existe".
- Las puntuaciones de confianza son heurísticas, no probabilidades calibradas.
- El módulo de brechas está sujeto al límite de uso de XposedOrNot.
- `phone.py` solo analiza el número (país, operador, tipo de línea); no identifica a su titular.
- Sin autenticación, protección CSRF ni base de datos: es una herramienta local de uso individual.
