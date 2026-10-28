# OSINTBODY

Herramienta educativa para consultar información pública a partir de un correo, nombre de usuario, dominio, teléfono o nombre.

## Instalación

```bash
python -m venv .venv

# Activar el entorno
source .venv/bin/activate        # Linux/macOS
source .venv/Scripts/activate    # Windows (Git Bash)
.venv\Scripts\activate           # Windows (CMD)

pip install -e ".[dev]"
```

## Dependencias

Las dependencias del proyecto no están fijadas por versión exacta. Para revisar avisos de
vulnerabilidades, instala `pip-audit` en un entorno aparte (no es una dependencia del proyecto) y
ejecuta, indicando el `site-packages` del entorno del proyecto:

```bash
pip-audit --path .venv/Lib/site-packages   # ejemplo (Windows); en Linux/macOS la ruta suele ser .venv/lib/python3.X/site-packages
```

El aviso PYSEC-2026-4320 (CA comprometidas en `certifi` anterior a 2026.10.18) se corrige en
tu entorno con `pip install "certifi>=2026.10.19"`; no está fijado en `pyproject.toml`.

## Uso en terminal

Inicia la interfaz interactiva de pantalla completa:

```powershell
osintbody
```

Usa las flechas y Enter para navegar, espacio para marcar módulos y Escape para volver al menú.
El menú permite iniciar una investigación, consultar los módulos disponibles y abrir el sitio web local.
En la selección de módulos, las fuentes externas aparecen desmarcadas inicialmente; selecciónalas
solo cuando quieras permitir consultas de red.

```powershell
osintbody --help
osintbody --version
```

Usa `osintbody --help` para ver las opciones disponibles.

## Uso web

Selecciona **Abrir sitio web** en el menú de terminal. El sitio se sirve localmente en:

<http://127.0.0.1:5000>

El servidor solo escucha en tu equipo.
El modo privado está activado inicialmente y ejecuta análisis locales, como los metadatos del teléfono.
Desmárcalo para habilitar las fuentes externas compatibles con los datos ingresados; se seleccionan
automáticamente y puedes desactivar fuentes concretas en **Personalizar fuentes externas**.
La pantalla indica qué datos puede recibir cada fuente antes de iniciar la búsqueda. El avance muestra
los resultados; después puedes filtrar hallazgos, relaciones y comprobaciones por módulo,
estado y texto antes de pulsar **Generar informe**. Los totales de cobertura conservan también
las comprobaciones ocultas por filtros. Los resultados se muestran en bloques de 50 filas para
mantener manejables las tablas extensas.
El teléfono acepta E.164 para cualquier país o un número nacional acompañado de su región
ISO 3166-1 alfa-2 (por ejemplo, `US`, `GB` o `CO`); el resultado se normaliza a E.164.
Los números nacionales sin región se rechazan porque su prefijo y longitud no identifican un país
de forma inequívoca.

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

La fuente **Perfil de GitHub por username** consulta una sola vez la API pública (sin clave) y
recoge los identificadores que el perfil declara: web, cuenta de Twitter/X y email público. Esos
pivotes unen perfiles en el grafo (por ejemplo, un perfil de `x.com/ana` con la cuenta de Twitter
declarada en GitHub). Son pistas declaradas, no prueba de identidad; el email público queda en el
grafo y en `report.json`.

## Limitaciones de seguridad

El dataset WhatsMyName (`OSINT_WMN_FILE`) se trata como entrada no confiable. Para reducir el
riesgo, solo se usan plantillas `https` con host público y se descartan las de `localhost`, IP
literales privadas, loopback o link-local y otros esquemas. Al cargar el dataset se registra
(nivel INFO) cuántas plantillas se descartaron, sin sus URLs.
No se comprueba a qué IP resuelve un nombre de host: un host público
cuyo DNS apunte a una IP privada (o un cambio de DNS entre comprobación y consulta) no se detecta.

Si el dataset falta o no se puede leer, el índice de cuentas se reduce a los alias integrados y se
registra un aviso local (WARNING) con solo el tipo de error, sin rutas. El informe
(`report.json` y HTML) no cambia por ello. El aviso puede repetirse varias veces por búsqueda.

Los números de teléfono no válidos ya no se escriben en los logs.

## Estado del proyecto

El proyecto está cerrado a nuevas funcionalidades. Limitaciones conocidas:

- Los handles de cuenta se normalizan a minúsculas, así que dos cuentas que solo difieren en
  mayúsculas se tratan como la misma.
- El índice de cuentas solo usa las plantillas WhatsMyName donde la cuenta es el último segmento
  de la ruta; el resto no se reconoce al correlacionar URLs.
- Un host público que resuelva a una IP privada no se detecta (ver arriba).
- El email público de GitHub aparece en claro en el grafo y en `report.json`.
