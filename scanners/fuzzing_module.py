#!/usr/bin/env python3

from utils.voice_utils import speak_text
import requests
import time
import os
import json
from datetime import datetime
import concurrent.futures
import random
import re
import sys

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Lista de agentes de usuario para rotar y evitar bloqueos
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
]

# Lista de palabras comunes para fuzzing de directorios
COMMON_DIRS = [
    "admin", "administrator", "backup", "backups", "config", "dashboard",
    "db", "debug", "default", "files", "home", "images", "img", "index",
    "js", "log", "login", "logs", "old", "panel", "private", "root",
    "secret", "secrets", "secure", "security", "temp", "test", "upload",
    "uploads", "user", "users", "webadmin", "wp-admin", "wp-content", "wp-includes"
]

# Extensiones comunes para archivos
COMMON_EXTENSIONS = [
    "", ".html", ".php", ".asp", ".aspx", ".jsp", ".js", ".txt", ".pdf", ".zip",
    ".bak", ".old", ".backup", ".config", ".conf", ".db", ".sql", ".xml", ".log",
    ".tar", ".tar.gz", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
]

# Diccionarios incorporados para fuzzing
BASIC_WORDLISTS = {
    "directories": [
        "admin", "administrator", "backup", "backups", "css", "data", "db", "debug", "dev",
        "files", "images", "img", "js", "log", "logs", "old", "panel", "private", "scripts",
        "secret", "secrets", "secure", "security", "temp", "test", "upload", "uploads", "web"
    ],
    "files": [
        "admin.php", "backup.sql", "config.php", "db.sql", "debug.log", "index.php", "info.php",
        "login.php", "phpinfo.php", "robots.txt", "server-status", "test.php", "web.config", ".env",
        ".git/HEAD", ".htaccess", "wp-config.php", "config.json", "credentials.txt"
    ]
}


def run_fuzzing_scan(target_url, voice_enabled=True):
    """Función principal para ejecutar un escaneo de fuzzing desde el módulo principal

    Args:
        target_url (str): URL objetivo para el fuzzing
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del fuzzing
    """
    try:
        # Anunciar inicio de fuzzing con voz
        speak_text(
            f"Iniciando análisis de fuzzing en {target_url}", voice_enabled)

        # Ejecutar el fuzzing con parámetros predeterminados
        results = run_fuzzing(
            target_url,
            mode='both',            # Escanear tanto directorios como archivos
            max_threads=10,         # 10 hilos concurrentes
            delay=0.1,              # 100ms entre solicitudes
            timeout=5,              # 5 segundos de timeout
            verify_ssl=True         # Verificar certificados SSL
        )

        # Anunciar finalización con voz
        total_dirs = len(results.get('directories', []))
        total_files = len(results.get('files', []))
        total = total_dirs + total_files

        speak_text(
            f"Análisis de fuzzing completado. Se encontraron {total} recursos en {target_url}",
            voice_enabled
        )

        # Mostrar resultados formateados
        display_fuzzing_results(results)

        return results

    except Exception as e:
        error_msg = f"Error durante el análisis de fuzzing: {e}"
        print(f"\n[!] {error_msg}")
        speak_text(error_msg, voice_enabled)
        return {"error": error_msg}
