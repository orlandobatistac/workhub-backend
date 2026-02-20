#!/bin/bash
# Script de instalación para WorkHub - Linux/Mac

set -e

echo "=================================================="
echo "🚀 INSTALADOR DE WORKHUB"
echo "=================================================="
echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker no está instalado"
    echo "📥 Descarga desde: https://www.docker.com/products/docker-desktop"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose no está instalado"
    echo "📥 Descarga desde: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker detectado: $(docker --version)"
echo "✅ Docker Compose detectado: $(docker-compose --version)"
echo ""

# Crear archivo .env si no existe
if [ ! -f ".env" ]; then
    echo "📝 Creando archivo de configuración (.env)..."
    cp .env.example .env
    
    # Generar SECRET_KEY seguro
    SECRET=$(openssl rand -base64 32)
    sed -i "s/your-secret-key-here/$SECRET/" .env
    
    echo "✅ Archivo .env creado"
    echo "   Nueva SECRET_KEY generada"
else
    echo "⏭️  Archivo .env ya existe (usando configuración existente)"
fi

echo ""
echo "🔨 Construyendo contenedores..."
docker-compose build --quiet

echo ""
echo "🚀 Iniciando servicios..."
docker-compose up -d

echo ""
echo "⏳ Esperando a que MariaDB esté listo..."
sleep 10

echo ""
echo "✅ INSTALACIÓN COMPLETADA"
echo ""
echo "=================================================="
echo "📊 ESTADO DEL SISTEMA"
echo "=================================================="
docker-compose ps
echo ""
echo "🌐 ACCESO:"
echo "   API:       http://localhost:8000"
echo "   Docs:      http://localhost:8000/docs"
echo "   Health:    http://localhost:8000/api/health"
echo ""
echo "💾 BASE DE DATOS:"
echo "   Host: localhost"
echo "   Puerto: 3306 (interno)"
echo "   Usuario: workhub"
echo "   Database: workhub"
echo ""
echo "🛑 PARA DETENER:"
echo "   docker-compose down"
echo ""
echo "📝 PARA VER LOGS:"
echo "   docker-compose logs -f"
echo ""
echo "=================================================="
