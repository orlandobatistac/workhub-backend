@echo off
cd /d "%~dp0"

REM Verificar Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Docker no esta instalado
    echo.
    echo Descarga desde: https://www.docker.com/products/docker-desktop
    echo.
    pause
    exit /b 1
)

REM Crear .env si no existe
if not exist ".env" (
    copy .env.example .env >nul
)

REM Detener y limpiar
docker-compose down --remove-orphans 2>nul

REM Construir e iniciar
echo.
echo Iniciando WorkHub...
echo.
docker-compose up --build -d

REM Esperar a MariaDB
timeout /t 15 /nobreak >nul

REM Ver estado
cls
echo.
echo ====================================
echo WORKHUB INSTALADO Y CORRIENDO
echo ====================================
echo.
docker-compose ps
echo.
echo Abre en el navegador:
echo http://localhost:8000/docs
echo.
pause
