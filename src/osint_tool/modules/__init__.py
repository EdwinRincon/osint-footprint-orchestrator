"""Autodescubrimiento de módulos.

Al importar este paquete se importan todos los archivos de la carpeta, y cada
uno se registra solo con `@register`. Añadir una fuente nueva = crear un archivo.
"""

import importlib
import pkgutil

for _info in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_info.name}")