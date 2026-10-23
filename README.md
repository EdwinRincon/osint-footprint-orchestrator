# OSINT Tool

Herramienta educativa para consultar información pública a partir de un correo, nombre de usuario, dominio, teléfono internacional o nombre.

## Instalación

```bash
python -m venv .venv

# Activar el entorno
source .venv/bin/activate        # Linux/macOS
source .venv/Scripts/activate    # Windows (Git Bash)
.venv\Scripts\activate           # Windows (CMD)

pip install -e ".[dev]"
```

La instalación editable usa directamente el código fuente del proyecto. Para ver el grafo como imagen, instala también [Graphviz](https://graphviz.org/download/); sin él se conserva el archivo `graph.dot`.

## Uso en terminal

Inicia la interfaz interactiva de pantalla completa:

```powershell
osint
```

Usa las flechas y Enter para navegar, espacio para marcar módulos y Escape para volver al menú.
La CLI es interactiva

```powershell
osint --help
osint --version
```

Se puede indicar más de un dato. Usa `osint --help` para ver todas las opciones.

## Uso web

Inicia el servidor local:

```powershell
python -m osint_tool.web.app
```

Abre <http://127.0.0.1:5000> en el navegador. El servidor solo escucha en tu equipo.
El formulario muestra qué análisis se aplican a las entradas: DNS y WHOIS al proporcionar
un dominio; comprobaciones de username, brechas de email y metadatos de teléfono cuando
corresponda. theHarvester es opcional y se activa explícitamente. La búsqueda muestra el
avance; después puedes explorar y filtrar hallazgos, relaciones y comprobaciones por módulo,
estado y texto antes de pulsar **Generar informe**. Los totales de cobertura conservan también
las comprobaciones ocultas por filtros.

## Informes

Al generar un informe, cada búsqueda guarda los resultados en una carpeta nueva dentro de
`reports/`: `report.html`, `report.json`, el grafo interactivo `graph.html` y `graph.dot`
(también `graph.png` si Graphviz está instalado). La visualización interactiva se distribuye
localmente y funciona sin depender de una CDN. Las relaciones identifican su evidencia y son
asociaciones observadas, no pruebas de identidad común.

En el grafo puedes arrastrar y seleccionar nodos/aristas para consultar la evidencia, reajustar
la distribución o descargar una imagen PNG. Los nodos representan identificadores observados;
no se fusionan cuentas de distintos servicios solo por compartir un username.

### Demostración ilustrativa (datos ficticios)

Este ejemplo explica cómo leer un informe; no es una consulta real ni afirma que la cuenta
pertenezca a una persona:

```text
Entrada: username=demo_user
WhatsMyName / Sitio A: encontrado (HTTP 200)
WhatsMyName / Sitio B: no encontrado (HTTP 404)
WhatsMyName / Sitio C: inconcluso (HTTP 429)

Relación:
  username:demo_user -> profile:https://example.test/demo_user
  evidencia: Sitio A · confianza heurística: 0.50
```

El informe conserva el total de comprobaciones por estado aunque se filtren sitios para su
presentación. `example.test` es un dominio reservado para documentación.

Usa la herramienta solo con datos propios o ficticios, con fines educativos y respetando la normativa y los términos de cada fuente. Los informes pueden contener datos personales: guárdalos de forma segura.
