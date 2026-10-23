"""Servicio de investigación: punto único de entrada para la CLI y la web.

Ejecuta los módulos, aísla sus fallos, correlaciona los hallazgos
y devuelve un `Report`. No sabe nada de formatos de salida ni de interfaces.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence

import requests

import osint_tool.modules  # noqa: F401  (el import registra todos los módulos)
from osint_tool.correlator import correlate
from osint_tool.external_errors import ExternalToolError
from osint_tool.models import (
    Finding,
    ModuleOutput,
    ModuleResult,
    Report,
    SourceCheck,
    Status,
    Target,
)
from osint_tool.registry import (
    Module,
    ModuleSkipped,
    ProgressAwareModule,
    applicable_modules,
)

logger = logging.getLogger(__name__)

# Fallos previsibles de una fuente: red, herramienta externa, ficheros y datos mal formados.
EXPECTED_ERRORS = (requests.RequestException, ExternalToolError, OSError, ValueError)

NO_MODULES_NOTE = (
    "Ningún módulo acepta los datos de entrada indicados: no se consultó ninguna fuente."
)

ProgressCallback = Callable[[ModuleResult, int, int], None]
ModuleProgressCallback = Callable[[str, int, int], None]


# Evitar mensajes HTTP completos impide reflejar en informes URLs con identificadores.
def _describe_failure(exc: Exception) -> str:
    """Texto seguro para el informe.

    Los mensajes de `requests` incluyen la URL consultada (con el email o el username),
    así que solo los errores propios, redactados por nosotros, conservan su mensaje.
    """
    if isinstance(exc, ExternalToolError):
        return str(exc)
    return type(exc).__name__


# Normalizar ambos contratos permite que el orquestador procese módulos antiguos y nuevos.
def _run_module(module: Module, target: Target) -> ModuleOutput:
    """Ejecuta el módulo y unifica su retorno (lista o `ModuleOutput`)."""
    output = module.run(target)
    if isinstance(output, ModuleOutput):
        return output
    return ModuleOutput(findings=output)


# Aislar cada ejecución permite informar fallos sin cancelar el resto de las fuentes.
def _execute(module: Module, target: Target) -> ModuleResult:
    """Ejecuta un módulo y traduce su desenlace a un `ModuleResult`."""
    start = time.perf_counter()
    status = Status.OK
    error: str | None = None
    findings: list[Finding] = []
    source_checks: list[SourceCheck] = []
    try:
        output = _run_module(module, target)
        findings, source_checks = output.findings, output.source_checks
    except ModuleSkipped as exc:
        status, error = Status.SKIPPED, str(exc)
    except EXPECTED_ERRORS as exc:
        logger.warning("Módulo %s falló: %s", module.name, type(exc).__name__)
        status, error = Status.ERROR, _describe_failure(exc)
    except Exception as exc:  # Keep one faulty module from stopping the remaining sources.
        logger.error("Módulo %s con error inesperado: %s", module.name, type(exc).__name__)
        status, error = Status.ERROR, f"Error inesperado ({type(exc).__name__})"
    return ModuleResult(
        name=module.name,
        status=status,
        findings=findings,
        error=error,
        duration=round(time.perf_counter() - start, 3),
        source_checks=source_checks,
    )


# Centralizar el flujo conserva el mismo informe para CLI, web y terminal interactiva.
def run_investigation(
    target: Target,
    modules: Sequence[Module] | None = None,
    on_progress: ProgressCallback | None = None,
    on_module_progress: ModuleProgressCallback | None = None,
) -> Report:
    """Investiga un `Target` y devuelve el informe completo.

    Args:
        target: datos de entrada ya validados.
        modules: módulos a ejecutar. Si es None, todos los que aceptan algún
            dato del Target. La CLI pasa aquí la selección de `--modules`.
        on_progress: callback opcional invocado al terminar cada módulo.
        on_module_progress: callback opcional para el progreso interno de módulos.
    """
    if modules is None:
        modules = applicable_modules(target)

    results: list[ModuleResult] = []
    total = len(modules)
    for completed, module in enumerate(modules, start=1):
        if on_module_progress is not None:
            on_module_progress(module.name, 0, 0)
            if isinstance(module, ProgressAwareModule):
                progress_callback = on_module_progress

                # La identidad capturada evita atribuir progreso tardío al módulo siguiente.
                def report_module_progress(
                    current: int,
                    maximum: int,
                    callback: ModuleProgressCallback = progress_callback,
                    module_name: str = module.name,
                ) -> None:
                    # Capturar la identidad del módulo evita asociar progreso tardío al siguiente.
                    callback(module_name, current, maximum)

                module.set_progress_callback(report_module_progress)
        try:
            result = _execute(module, target)
        finally:
            if isinstance(module, ProgressAwareModule):
                module.set_progress_callback(None)
        results.append(result)
        if on_progress is not None:
            on_progress(result, completed, total)

    findings = [finding for result in results for finding in result.findings]
    report = Report(target=target, results=results, relations=correlate(target, findings))
    if not results:
        report.notes.append(NO_MODULES_NOTE)
    return report
