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
echo ====================================
echo INSTALANDO WORKHUB
echo ====================================
echo.
docker-compose up --build -d

REM Esperar a que los servicios estén listos
timeout /t 20 /nobreak >nul

REM Ver estado
cls
echo.
echo ====================================
echo WORKHUB INSTALADO Y CORRIENDO
echo ====================================
echo.
docker-compose ps
echo.
echo URLs:
echo   Frontend: http://localhost:3000
echo   Backend:  http://localhost:8000/docs
echo.
pause
