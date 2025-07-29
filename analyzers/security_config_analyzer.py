#!/usr/bin/env python3

from utils.voice_utils import speak_text
import nmap
import json
import os
import re
import time
import sys
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Definiciones de configuraciones seguras recomendadas
SECURITY_BENCHMARKS = {
    "ssh": {
        "port": 22,
        "secure_configs": [
            {"name": "Protocol 2",
                "description": "Usar solo el protocolo SSH versión 2", "severity": "ALTO"},
            {"name": "PermitRootLogin no",
                "description": "Deshabilitar login directo como root", "severity": "ALTO"},
            {"name": "PasswordAuthentication no",
                "description": "Deshabilitar autenticación por contraseña", "severity": "MEDIO"},
            {"name": "PubkeyAuthentication yes",
                "description": "Habilitar autenticación por clave pública", "severity": "ALTO"},
            {"name": "PermitEmptyPasswords no",
                "description": "No permitir contraseñas vacías", "severity": "ALTO"},
            {"name": "X11Forwarding no",
                "description": "Deshabilitar reenvío X11", "severity": "MEDIO"},
            {"name": "MaxAuthTries 4",
                "description": "Limitar intentos de autenticación", "severity": "MEDIO"},
            {"name": "ClientAliveInterval 300",
                "description": "Configurar tiempo de inactividad", "severity": "BAJO"},
            {"name": "ClientAliveCountMax 0",
                "description": "Desconectar después de tiempo de inactividad", "severity": "BAJO"}
        ]
    },
    "http": {
        "port": 80,
        "secure_configs": [
            {"name": "X-Frame-Options",
                "description": "Protección contra ataques de clickjacking", "severity": "MEDIO"},
            {"name": "X-Content-Type-Options",
                "description": "Prevenir MIME-sniffing", "severity": "MEDIO"},
            {"name": "Content-Security-Policy",
                "description": "Mitigar XSS y otras vulnerabilidades", "severity": "ALTO"},
            {"name": "Strict-Transport-Security",
                "description": "Forzar conexiones HTTPS", "severity": "ALTO"},
            {"name": "X-XSS-Protection",
                "description": "Protección contra XSS", "severity": "MEDIO"},
            {"name": "Referrer-Policy",
                "description": "Controlar información del referrer", "severity": "BAJO"}]