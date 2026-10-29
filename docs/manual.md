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