# OSINTBODY

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

## Uso en terminal

Inicia la interfaz interactiva de pantalla completa:

```powershell
osintbody
```

Usa las flechas y Enter para navegar, espacio para marcar módulos y Escape para volver al menú.
El menú permite iniciar una investigación, consultar los módulos disponibles y abrir el sitio web local.

```powershell
osintbody --help
osintbody --version
```

Usa `osintbody --help` para ver las opciones disponibles.

## Uso web

Selecciona **Abrir sitio web** en el menú de terminal. El sitio se sirve localmente en:

<http://127.0.0.1:5000>

El servidor solo escucha en tu equipo.
El formulario muestra qué análisis se aplican a las entradas: DNS y WHOIS al proporcionar
un dominio; comprobaciones de username, brechas de email y metadatos de teléfono cuando
corresponda. theHarvester es opcional y se activa explícitamente. La búsqueda muestra el
avance; después puedes explorar y filtrar hallazgos, relaciones y comprobaciones por módulo,
estado y texto antes de pulsar **Generar informe**. Los totales de cobertura conservan también
las comprobaciones ocultas por filtros. Los resultados se muestran en bloques de 50 filas para
mantener manejables las tablas extensas.

## Informes

Al generar un informe, cada búsqueda guarda los resultados en una carpeta nueva dentro de
`reports/`: `report.html`, `report.json` y los recursos del grafo interactivo, incluido
`graph.html`. Desde la web puedes abrir o descargar el informe HTML, descargar los datos JSON
y abrir el grafo interactivo por separado; el informe HTML no incorpora el grafo. Las tablas
extensas del informe se pueden desplegar bajo demanda. La visualización se distribuye localmente
y funciona sin depender de una CDN.
Las relaciones identifican su evidencia y son asociaciones observadas, no pruebas de identidad
común.

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
