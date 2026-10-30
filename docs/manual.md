## Have I Been Pwned

El módulo opcional `hibp` consulta la API v3 de Have I Been Pwned para buscar brechas asociadas a
un correo. Envía ese correo a un tercero y, como las demás fuentes de red, está desactivado por
defecto; selecciónalo explícitamente solo si tienes autorización para hacerlo.

Configura una clave de API en el entorno local antes de ejecutar el módulo:

```bash
export OSINT_HIBP_API_KEY="tu-clave-api"
```

Sin clave, el módulo no realiza consultas de red y registra cobertura `not_configured`. Nunca usa
resultados simulados o de ejemplo. HTTP 404 significa que no se informó de brechas; HTTP 429 es
inconcluso y los demás errores HTTP, de red o de formato de respuesta se registran como errores.

## Sesiones y pivotes

Las investigaciones interactivas de Textual se guardan como sesiones locales bajo
`OSINT_OUTPUT_DIR/sessions/`. Cada sesión mantiene los informes de sus entradas y un grafo en
`session.json`. Los informes de sesión omiten los payloads `raw`, redactan claves detectables y
no guardan URLs de petición; las URLs de fuente se conservan sin query ni fragmento. La interfaz
web no expone estas carpetas; la gestión de sesiones está disponible en Textual.
Los ficheros de sesión e informes se guardan con permisos privados (`0700` en carpetas y `0600` en
ficheros).

Los pivotes pueden venir del valor exacto de un hallazgo validado o de un correo que el módulo
declare explícitamente. Los valores de hallazgo que pasan para más de un tipo aparecen una vez por
tipo; los pivotes declarados solo se aceptan como correo explícito. No se ofrecen gravatars ni
pivotes implícitos, y no se extraen nombres de usuario de URLs ni se derivan dominios o partes de
correos.
Antes de ejecutar el objetivo inicial, la interfaz muestra el objetivo, los módulos seleccionados y
sus destinatarios; solo tras la aceptación explícita crea la sesión y ejecuta las consultas. Para
cada pivote, también muestra la evidencia, la fuente, los módulos y los destinatarios externos.
Ambas confirmaciones empiezan desmarcadas y no se ejecuta nada sin aceptación explícita. Los
módulos de red siguen desactivados por defecto.

El límite máximo por sesión es profundidad 2 y 10 objetivos, contando el inicial. Se pueden reducir
localmente con `OSINT_SESSION_MAX_DEPTH` (0–2) y `OSINT_SESSION_MAX_TARGETS` (1–10); valores
superiores a esos máximos se rechazan. Los objetivos repetidos se detectan tras normalizar tipo,
mayúsculas/minúsculas, espacios y formato telefónico. Una entrada fallida queda marcada en el grafo
y no borra los resultados anteriores. Cada arista se etiqueta como hipótesis no verificada, no como
una identidad confirmada. La opción «Historial local» permite consultar las sesiones guardadas y
eliminarlas, pero no reanudarlas. Al listar, una sesión guardada con entradas marcadas `running` se
muestra como `interrupted` sin modificar su `session.json`; las sesiones con una versión de esquema
no compatible se identifican y también pueden eliminarse.
Desde la pantalla de sesión o el historial local se pueden eliminar una sesión y sus informes.