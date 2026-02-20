# Guía de Despliegue Backend (Workhub API)

Esta guía describe los pasos para desplegar el backend (API) del proyecto **Workhub** en un servidor Linux (Ubuntu/Debian).

## 📋 Requisitos Previos

*   **Python**: Versión 3.10 o superior (Requerido: `python3.10-venv` o similar).
*   **Base de Datos**: SQLite (Por defecto, no requiere instalación extra).

### Recursos Mínimos Recomendados

*   **CPU**: 1 vCPU
*   **RAM**: 512MB (Para ejecutar Uvicorn con 1 worker).
*   **Disco**: 5GB de espacio libre.

---

## 🚀 Paso a Paso

### 1. Clonar el Repositorio

Accede al servidor y clona el proyecto backend (asumiendo que está en un repo separado `workhub-backend`):

```bash
# Ejemplo: clonar en /var/www/workhub-backend
cd /var/www
git clone <URL_DEL_REPO_BACKEND> workhub-backend
cd workhub-backend
```

### 2. Configurar Entorno Python

Crea un entorno virtual para aislar las dependencias:

```bash
# Instalar venv si no lo tienes
sudo apt update && sudo apt install python3-venv

# Crear entorno virtual
python3 -m venv .venv

# Activar entorno
source .venv/bin/activate
```

### 3. Instalar Dependencias

Con el entorno activado (verás `(.venv)` en tu terminal):

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuración (.env)

Copia el archivo de ejemplo y configura las variables críticas:

```bash
cp .env.example .env
nano .env
```

**Variables Importantes a modificar:**
*   `SECRET_KEY`: **CRÍTICO**. Genera una nueva cadena segura (puedes usar `openssl rand -hex 32`).
*   `CORS_PATTERN`: Ajusta esto para permitir peticiones desde tu frontend.
    *   Si el frontend está en el mismo dominio: `https?://(tu-dominio\.com)`
    *   Si es desarrollo local: `https?://(localhost|.*\.github\.dev)`

### 5. Probando la Ejecución

Prueba que la API arranca correctamente:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
*(Presiona Ctrl+C para detener después de verificar que no hay errores)*.

---

## ⚙️ Configuración para Producción (Daemon)

Para mantener la API corriendo en segundo plano y que reinicie automáticamente, usa **Systemd**.

1.  Crea el archivo de servicio: `sudo nano /etc/systemd/system/workhub-api.service`

```ini
[Unit]
Description=Gunicorn instance to serve Workhub API
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/workhub-backend
Environment="PATH=/var/www/workhub-backend/.venv/bin"
ExecStart=/var/www/workhub-backend/.venv/bin/uvicorn main:app --workers 3 --worker-class uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000

[Install]
WantedBy=multi-user.target
```
*Ajusta `User`, `Group` y `WorkingDirectory` según tu caso.*

2.  Inicia y habilita el servicio:
```bash
sudo systemctl start workhub-api
sudo systemctl enable workhub-api
```

---

## 🌐 Configuración del Servidor Web (Nginx)

Configura Nginx para redirigir las peticiones `/api` a tu backend (funcionando en el puerto 8000).

Edita tu archivo de configuración de Nginx (el mismo que usaste para el frontend):

```nginx
server {
    listen 80;
    server_name tu-dominio.com;

    # Frontend (React)
    root /var/www/workhub/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Backend (FastAPI)
    # Redirige todo lo que empiece por /api al backend
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Reinicia Nginx: `sudo systemctl restart nginx`

Tu API ahora debería estar accesible en `http://tu-dominio.com/api/health`.

---

## 🛠 Solución de Problemas

*   **Error 502 Bad Gateway:** El backend no está corriendo. Revisa el estado con `sudo systemctl status workhub-api`.
*   **Errores de CORS en el navegador:** Verifica la variable `CORS_PATTERN` en el `.env` del backend. Asegúrate de incluir el dominio desde donde sirves el frontend.
*   **Base de datos vacía:** La base de datos SQLite (`workhub.db`) se creará automáticamente en la carpeta de trabajo al iniciar la aplicación. Asegúrate de que el usuario del servicio (`www-data`) tenga permisos de escritura en la carpeta.
    ```bash
    chown -R www-data:www-data /var/www/workhub-backend
    ```
