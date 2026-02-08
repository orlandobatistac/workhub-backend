# Códigos de error estándar (API)

Este documento describe la forma estándar de los errores retornados por la API y los códigos de error que el frontend debe manejar de forma predecible.

## Formato de respuesta de error (estándar)
Todas las respuestas de error siguen esta estructura preferida:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human readable message",
    "details": [ ... ]  // opcional, por ejemplo para errores de validación
  }
}
```

- `error.code` (string): identificador programático (snake_case). Úsalo en el frontend para decidir flujo/UX.
- `error.message` (string): mensaje legible por humanos, en inglés (para consistencia).
- `error.details` (list | any): información adicional; para errores de validación contiene la lista de errores (campo, mensaje, etc.).

> Nota: por compatibilidad con ciertas capas de FastAPI algunos handlers pueden devolver `{ "detail": {"error": {...}} }`. Los clientes deberían primero buscar `body.error` y, si no existe, `body.detail.error`.

---

## Códigos de error y significados (selección)

| Código | HTTP | Mensaje (ejemplo) | Notas |
|---|---:|---|---|
| `validation_error` | 422 | "Validation error" | `details` contiene lista de pydantic errors o detalles serializables. |
| `authentication_required` | 401 | "Authentication required" | Usuario no autenticado. |
| `invalid_credentials` | 401 | "Invalid credentials" | Login fallido. |
| `user_inactive` | 401 | "User inactive" | Credenciales válidas pero usuario inactivo. |
| `forbidden` | 403 | "Access to this resource is forbidden" | Falta de permisos. |
| `ticket_not_found` | 404 | "Ticket not found" | Recurso no encontrado. |
| `user_not_found` | 404 | "User not found" | Recurso no encontrado. |
| `branch_not_found` | 404 | "Branch not found" | Recurso no encontrado. |
| `workgroup_not_found` | 404 | "Workgroup not found" | Recurso no encontrado. |
| `email_in_use` | 400 | "Email already in use" | Conflicto de datos de entrada. |
| `username_in_use` | 400 | "Username already in use" | Conflicto de datos de entrada. |
| `attachment_too_large` | 400 | "Attachment too large: {filename}" | Tamaño máximo por archivo (10MB por archivo). |
| `attachment_too_many` | 400 | "Too many attachments: max 5 files allowed" | Número máximo de attachments permitidos (5 archivos). |
| `missing_content` | 422 | "Missing content" | Falta `content` en mensaje. |
| `rate_limited` | 429 | "Rate limit exceeded" | Límite de peticiones alcanzado. |

---

## Ejemplos

- Validación (422):

```json
{
  "error": {
    "code": "validation_error",
    "message": "Validation error",
    "details": [
      {"loc": ["body", "subject"], "msg": "field required", "type": "value_error.missing"},
      {"loc": ["body", "priority"], "msg": "priority must be one of ['high','low','medium','urgent']", "type": "value_error"}
    ]
  }
}
```

- Error programático simple (404):

```json
{ "error": { "code": "ticket_not_found", "message": "Ticket not found" } }
```

- Attachment demasiado grande (400):

```json
{ "error": { "code": "attachment_too_large", "message": "Attachment too large: big.bin" } }
```

---

## Recomendaciones para el frontend

- Priorizar `error.code` para lógica de UI (p. ej., mostrar pantalla de login cuando `authentication_required`).
- Mostrar `error.message` como fallback legible; si `details` existe, mostrar entradas relevantes (por ejemplo, mensajes de validación por campo).
- Implementar un mapeo central de `error.code -> i18n key` en el frontend si necesitan localización.

---

## Mantenimiento

- Al añadir un nuevo `error.code`, actualiza `docs/ERRORS.md` y agrega un test que verifique la respuesta para ese caso.
- Evitar cambios en códigos existentes; usar códigos nuevos y mantener retrocompatibilidad.

---

Si quieres, puedo:
- Añadir un archivo JSON de contrato (OpenAPI extensions o ejemplos) que el frontend pueda importar automáticamente. ✅
- Añadir tests que garanticen que cada endpoint documentado devuelva `error` con la estructura correcta en todos los casos de fallo. ✅
