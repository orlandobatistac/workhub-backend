# Setup WorkHub System

## Requisitos

- **Docker Desktop** descargado e instalado
  - Windows: https://www.docker.com/products/docker-desktop
  - Mac: https://www.docker.com/products/docker-desktop
  - Linux: Instala Docker y Docker Compose desde tu gestor de paquetes

## Instalación Automática (Recomendado)

### Windows
```bash
install.bat
```

### Linux / macOS
```bash
chmod +x install.sh
./install.sh
```

## ¿Qué hace el instalador?

1. ✅ Verifica Docker está instalado
2. ✅ Crea archivo `.env` con configuración
3. ✅ Construye contenedores (Backend + Frontend + BD)
4. ✅ Inicia todos los servicios
5. ✅ Muestra URLs para acceder

## Después de la Instalación

Una vez completado, podrás acceder a:

| Servicio | URL |
|----------|-----|
| **Frontend** | http://localhost:3000 |
| **Backend API** | http://localhost:8000 |
| **API Docs** | http://localhost:8000/docs |

## Autenticación

Usuario: `admin`
Contraseña: `admin123`

## Comandos Útiles

```bash
# Ver estado
docker-compose ps

# Ver logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Reiniciar
docker-compose restart

# Detener
docker-compose down

# Eliminar todo (limpia BD)
docker-compose down -v
```

## Solución de Problemas

### Error: "Docker no está instalado"
→ Descarga desde https://www.docker.com/products/docker-desktop

### Puertos ya en uso
```bash
# Encontrar qué usa puerto 3000
netstat -ano | findstr :3000

# O cambiar en docker-compose.yml
# Cambiar "3000:3000" por "3001:3000" por ejemplo
```

### Reiniciar desde cero
```bash
docker-compose down -v
docker-compose up -d
```

## Soporte

Si tienes problemas, contacta al equipo de desarrollo.
