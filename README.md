# OSINT Tool

Herramienta educativa para consultar información pública a partir de un correo, nombre de usuario, dominio, teléfono internacional o nombre.

## Instalación desde el código fuente

Requiere Python 3.10 o superior. Desde la carpeta del proyecto:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

La instalación editable usa directamente el código fuente del proyecto. Para ver el grafo como imagen, instala también [Graphviz](https://graphviz.org/download/); sin él se conserva el archivo `graph.dot`.

## Uso en terminal

Inicia el asistente interactivo:

```powershell
osint
```

O ejecuta una consulta indicando el dato:

```powershell
osint --domain ejemplo.com
osint --email ana@ejemplo.com --format html
osint --list-modules
```

Se puede indicar más de un dato. Usa `osint --help` para ver todas las opciones.

## Uso web

Inicia el servidor local:

```powershell
python -m osint_tool.web.app
```

Abre <http://127.0.0.1:5000> en el navegador. El servidor solo escucha en tu equipo.

## Informes

Por defecto, cada consulta guarda sus resultados en una carpeta nueva dentro de `reports/`: `report.html`, `report.json` y el grafo `graph.dot` (también `graph.png` si Graphviz está instalado). En la web, el informe HTML se abre al terminar la consulta.

Usa la herramienta solo con datos propios o ficticios, con fines educativos y respetando la normativa y los términos de cada fuente. Los informes pueden contener datos personales: guárdalos de forma segura.
