-- Script de inicialización para MariaDB
-- Este script se ejecuta automáticamente al crear el contenedor de Docker

-- Asegurar que la base de datos existe con el charset correcto
CREATE DATABASE IF NOT EXISTS workhub 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

-- Usar la base de datos
USE workhub;

-- Configurar timezone
SET time_zone = '+00:00';

-- Mensaje de éxito
SELECT 'Base de datos WorkHub inicializada correctamente' AS status;
