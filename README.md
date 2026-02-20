# WorkHub API

Backend REST API para gestión de tickets y soporte.

## Instalación Rápida

### Windows

```bash
install.bat
```

La instalación descarga Docker, configura la base de datos y inicia el sistema automáticamente.

### Linux / macOS

```bash
chmod +x install.sh
./install.sh
```

## ¿Qué se instala?

- **Backend API**: FastAPI en puerto `8000`
- **Base de datos**: MariaDB en puerto `3306` (interno)
- **Documentación**: Swagger UI y ReDoc

## URLs Principales

| URL | Propósito |
|-----|-----------|
| http://localhost:8000/api/health | Estado del sistema |
| http://localhost:8000/docs | Documentación técnica (testing) |
| http://localhost:8000/redoc | Documentación (lectura) |

## Autenticación

**Usuario por defecto:**
```
Username: admin
Password: admin123
```

**Obtener token JWT:**
```bash
curl -X POST http://localhost:8000/api/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

**Usar token:**
```bash
curl -H "Authorization: Bearer {token}" \
  http://localhost:8000/api/branches
```

## API Endpoints

### Base: `/api`

| Recurso | GET | POST | PUT | DELETE |
|---------|-----|------|-----|--------|
| `/branches` | ✅ | ✅ | ✅ | ✅ |
| `/agents` | ✅ | ✅ | ✅ | ✅ |
| `/workgroups` | ✅ | ✅ | ✅ | ✅ |
| `/contacts` | ✅ | ✅ | ✅ | ✅ |
| `/tickets` | ✅ | ✅ | ✅ | ✅ |
| `/tickets/{id}/messages` | ✅ | ✅ | - | - |
| `/seed` | - | ✅ | - | - |

## Configuración

El archivo `.env` contiene las configuraciones. Creado automáticamente en la instalación.

**Si necesitas cambiar algo:**
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=workhub
DB_PASSWORD=workhub_password
DB_NAME=workhub
```

## Comandos Útiles

```bash
# Ver estado
docker-compose ps

# Ver logs
docker-compose logs backend

# Reiniciar
docker-compose restart

# Detener
docker-compose down

# Generar datos de prueba
curl -X POST http://localhost:8000/api/seed
```

## Soporte

Para reportar problemas o sugerencias, contacta al equipo de desarrollo.

