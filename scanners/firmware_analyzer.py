#!/usr/bin/env python3

from utils.voice_utils import speak_text
import os
import sys
import json
import re
import hashlib
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patrones comunes en firmware IoT
FIRMWARE_PATTERNS = {
    "hardcoded_credentials": {
        "pattern": r'(password|passwd|pwd|user|username)\s*[=:]\s*[\'\"](.*?)[\'\"]\'',
        "description": "Credenciales codificadas en el firmware",
        "severity": "CRÍTICO",
        "recommendation": "Eliminar credenciales hardcodeadas y utilizar mecanismos seguros de autenticación"
    },
    "private_keys": {
        "pattern": r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        "description": "Claves privadas en el firmware",
        "severity": "CRÍTICO",
        "recommendation": "Eliminar claves privadas del firmware y utilizar almacenamiento seguro de claves"
    },
    "debug_commands": {
        "pattern": r'(system|exec|popen|spawn)\s*\([\'\"].*?(sh|bash|cmd|telnet|nc|netcat)',
        "description": "Comandos de depuración o backdoors",
        "severity": "ALTO",
        "recommendation": "Eliminar comandos de depuración y backdoors del código de producción"
    },
    "insecure_functions": {
        "pattern": r'\b(strcpy|strcat|sprintf|gets|scanf)\s*\(',
        "description": "Funciones inseguras susceptibles a desbordamiento de buffer",
        "severity": "ALTO",
        "recommendation": "Reemplazar con alternativas seguras (strncpy, strncat, snprintf, fgets)"
    },
    "weak_crypto": {
        "pattern": r'\b(MD5|DES|RC4|SHA1)\b',
        "description": "Algoritmos criptográficos débiles o obsoletos",
        "severity": "MEDIO",
        "recommendation": "Actualizar a algoritmos criptográficos fuertes (SHA-256, AES)"
    },
    "sensitive_info": {
        "pattern": r'(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*[\'\"](.*?)[\'\"]\'',
        "description": "Información sensible en el firmware",
        "severity": "ALTO",
        "recommendation": "Eliminar información sensible del firmware y utilizar mecanismos seguros de almacenamiento"
    },
    "default_configs": {
        "pattern": r'(default[_-]?config|default[_-]?settings|factory[_-]?settings)',
        "description": "Configuraciones por defecto",
        "severity": "MEDIO",
        "recommendation": "Asegurar que las configuraciones por defecto sean seguras"
    },
    "update_mechanism": {
        "pattern": r'(update|upgrade|firmware).*?(http:|ftp:|telnet:)',
        "description": "Mecanismo de actualización inseguro",
        "severity": "ALTO",
        "recommendation": "Implementar actualizaciones sobre HTTPS con verificación de firma"
    }
}


def analyze_firmware_file(firmware_path, voice_enabled=False):
    """
    Analiza un archivo de firmware en busca de vulnerabilidades comunes

    Args:
        firmware_path (str): Ruta al archivo de firmware
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del análisis
    """
    try:
        print(f"\n[*] Analizando firmware: {firmware_path}")
        speak_text("Analizando archivo de firmware", voice_enabled)

        # Verificar si el archivo existe
        if not os.path.isfile(firmware_path):
            print(f"[!] El archivo {firmware_path} no existe")
            return None

        # Obtener información básica del archivo
        file_size = os.path.getsize(
            firmware_path) / (1024 * 1024)  # Tamaño en MB
        file_extension = os.path.splitext(firmware_path)[1].lower()

        # Calcular hash del archivo
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        with open(firmware_path, 'rb') as f:
            data = f.read()
            md5_hash.update(data)
            sha1_hash.update(data)
            sha256_hash.update(data)

        # Inicializar resultados
        results = {
            "firmware_file": firmware_path,
            "file_size_mb": round(file_size, 2),
            "file_extension": file_extension,
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [],
            "total_findings": 0,
            "severity_counts": {
                "CRÍTICO": 0,
                "ALTO": 0,
                "MEDIO": 0,
                "BAJO": 0,
                "INFORMATIVO": 0
            }
        }

        # Intentar leer el archivo como texto
        try:
            with open(firmware_path, 'r', errors='ignore') as f:
                content = f.read()

                # Buscar patrones en el contenido
                for pattern_name, pattern_info in FIRMWARE_PATTERNS.items():
                    matches = re.finditer(
                        pattern_info["pattern"], content, re.IGNORECASE)
                    for match in matches:
                        # Añadir hallazgo
                        finding = {
                            "type": pattern_name,
                            "description": pattern_info["description"],
                            "severity": pattern_info["severity"],
                            "recommendation": pattern_info["recommendation"],
                            "match": match.group(0),
                            "position": match.start()
                        }

                        results["findings"].append(finding)
                        results["severity_counts"][pattern_info["severity"]] += 1
                        results["total_findings"] += 1

        except Exception as e:
            print(f"[!] Error al leer el archivo como texto: {e}")
            print("[*] El archivo podría estar en formato binario")

        # Guardar resultados en archivo
        output_dir = "resultados_firmware"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/firmware_analysis_{os.path.basename(firmware_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

        # Mostrar resumen
        print(
            f"\n[+] Análisis completado. Se encontraron {results['total_findings']} hallazgos")
        print("Distribución por severidad:")
        for severity, count in results["severity_counts"].items():
            if count > 0:
                print(f"  - {severity}: {count}")

        print(f"[+] Resultados guardados en {filename}")
        speak_text(
            f"Análisis de firmware completado. Se encontraron {results['total_findings']} hallazgos", voice_enabled)

        return results

    except Exception as e:
        print(f"[!] Error al analizar firmware: {e}")
        return None


def run_firmware_analysis(firmware_path, voice_enabled=False):
    """
    Ejecuta un análisis completo de firmware IoT

    Args:
        firmware_path (str): Ruta al archivo de firmware
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del análisis
    """
    try:
        print(f"\n===== INICIANDO ANÁLISIS DE FIRMWARE IOT =====\n")
        speak_text("Iniciando análisis de firmware IoT", voice_enabled)

        # Verificar si se proporcionó una ruta de firmware
        if not firmware_path:
            print("[!] No se proporcionó una ruta de firmware para analizar")
            speak_text(
                "No se proporcionó una ruta de firmware para analizar", voice_enabled)
            return None

        # Analizar el firmware
        results = analyze_firmware_file(firmware_path, voice_enabled)

        if not results:
            print("[!] No se pudo analizar el firmware")
            speak_text("No se pudo analizar el firmware", voice_enabled)
            return None

        print("\n===== ANÁLISIS DE FIRMWARE COMPLETADO =====\n")
        speak_text("Análisis de firmware completado", voice_enabled)

        return results

    except Exception as e:
        print(f"[!] Error al ejecutar análisis de firmware: {e}")
        return None


# Función principal para pruebas
if __name__ == "__main__":
    # Ejemplo de uso
    firmware_path = "firmware.bin"
    run_firmware_analysis(firmware_path, False)