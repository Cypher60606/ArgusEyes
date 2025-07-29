#!/usr/bin/env python3

from utils.voice_utils import speak_text
import os
import sys
import json
import re
import subprocess
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patrones comunes de backdoors y rootkits
BACKDOOR_PATTERNS = {
    "suspicious_processes": {
        "description": "Procesos sospechosos en ejecución",
        "severity": "ALTO",
        "detection_method": "Análisis de procesos en ejecución",
        "recommendation": "Verificar la legitimidad de los procesos sospechosos y terminarlos si son maliciosos"
    },
    "hidden_files": {
        "description": "Archivos ocultos en directorios del sistema",
        "severity": "MEDIO",
        "detection_method": "Búsqueda de archivos ocultos",
        "recommendation": "Revisar los archivos ocultos y eliminar aquellos que sean sospechosos"
    },
    "modified_system_files": {
        "description": "Archivos del sistema modificados",
        "severity": "CRÍTICO",
        "detection_method": "Verificación de integridad de archivos",
        "recommendation": "Restaurar los archivos del sistema desde copias de seguridad confiables"
    },
    "suspicious_network_connections": {
        "description": "Conexiones de red sospechosas",
        "severity": "ALTO",
        "detection_method": "Análisis de conexiones de red activas",
        "recommendation": "Bloquear las conexiones sospechosas y revisar las reglas del firewall"
    },
    "unauthorized_scheduled_tasks": {
        "description": "Tareas programadas no autorizadas",
        "severity": "MEDIO",
        "detection_method": "Análisis de tareas programadas",
        "recommendation": "Eliminar las tareas programadas sospechosas"
    },
    "suspicious_registry_entries": {
        "description": "Entradas sospechosas en el registro (Windows)",
        "severity": "ALTO",
        "detection_method": "Análisis del registro del sistema",
        "recommendation": "Eliminar las entradas del registro sospechosas"
    },
    "unauthorized_users": {
        "description": "Usuarios no autorizados en el sistema",
        "severity": "CRÍTICO",
        "detection_method": "Análisis de cuentas de usuario",
        "recommendation": "Eliminar las cuentas de usuario no autorizadas"
    },
    "suspicious_startup_items": {
        "description": "Elementos de inicio sospechosos",
        "severity": "ALTO",
        "detection_method": "Análisis de elementos de inicio",
        "recommendation": "Eliminar los elementos de inicio sospechosos"
    }
}


def check_suspicious_processes(voice_enabled=False):
    """
    Busca procesos sospechosos en ejecución

    Args:
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        list: Lista de procesos sospechosos encontrados
    """
    try:
        print("\n[*] Buscando procesos sospechosos...")
        speak_text("Buscando procesos sospechosos", voice_enabled)

        suspicious_processes = []

        # Lista de nombres de procesos potencialmente maliciosos
        malicious_process_names = [
            "nc.exe", "netcat", "meterpreter", "backdoor", "keylogger",
            "rootkit", "trojan", "spyware", "adware", "malware",
            "exploit", "hack", "crack", "steal", "ransom", "crypto"
        ]

        # Obtener lista de procesos en ejecución
        if os.name == 'nt':  # Windows
            try:
                output = subprocess.check_output(
                    ["tasklist", "/FO", "CSV"], universal_newlines=True)
                # Saltar la primera línea (encabezado)
                for line in output.split('\n')[1:]:
                    if line.strip():
                        parts = line.strip('"').split('","')
                        process_name = parts[0] if parts else ""
                        pid = parts[1] if len(parts) > 1 else ""

                        # Verificar si el nombre del proceso coincide con alguno de la lista
                        for malicious_name in malicious_process_names:
                            if malicious_name.lower() in process_name.lower():
                                suspicious_processes.append({
                                    "name": process_name,
                                    "pid": pid,
                                    "reason": f"Nombre sospechoso: {malicious_name}"
                                })
                                break
            except Exception as e:
                print(
                    f"[!] Error al obtener lista de procesos en Windows: {e}")

        else:  # Linux/Unix
            try:
                output = subprocess.check_output(
                    ["ps", "aux"], universal_newlines=True)
                # Saltar la primera línea (encabezado)
                for line in output.split('\n')[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            user = parts[0]
                            pid = parts[1]
                            process_name = ' '.join(parts[10:])

                            # Verificar si el nombre del proceso coincide con alguno de la lista
                            for malicious_name in malicious_process_names:
                                if malicious_name.lower() in process_name.lower():
                                    suspicious_processes.append({
                                        "name": process_name,
                                        "pid": pid,
                                        "user": user,
                                        "reason": f"Nombre sospechoso: {malicious_name}"
                                    })
                                    break
            except Exception as e:
                print(
                    f"[!] Error al obtener lista de procesos en Linux/Unix: {e}")

        return suspicious_processes

    except Exception as e:
        print(f"[!] Error al buscar procesos sospechosos: {e}")
        return []


def check_suspicious_connections(voice_enabled=False):
    """
    Busca conexiones de red sospechosas

    Args:
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        list: Lista de conexiones sospechosas encontradas
    """
    try:
        print("\n[*] Buscando conexiones de red sospechosas...")
        speak_text("Buscando conexiones de red sospechosas", voice_enabled)

        suspicious_connections = []

        # Puertos comúnmente utilizados por malware
        suspicious_ports = [
            4444, 5555, 6666, 7777, 8888, 9999,  # Puertos comunes de backdoors
            1337, 31337, 54321, 12345,  # Puertos históricos de backdoors
            6667, 6668, 6669,  # IRC (comúnmente usado por botnets)
            445, 139, 135  # SMB/NetBIOS (comúnmente explotados)
        ]

        # Obtener conexiones de red activas
        if os.name == 'nt':  # Windows
            try:
                output = subprocess.check_output(
                    ["netstat", "-ano"], universal_newlines=True)
                # Saltar las primeras líneas (encabezado)
                for line in output.split('\n')[4:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5 and ("TCP" in parts[0] or "UDP" in parts[0]):
                            protocol = parts[0]
                            local_address = parts[1]
                            remote_address = parts[2]
                            state = parts[3] if "TCP" in protocol else "N/A"
                            pid = parts[4] if "TCP" in protocol else parts[3]

                            # Extraer puerto remoto
                            remote_port = int(
                                remote_address.split(':')[-1]) if ':' in remote_address else 0

                            # Verificar si el puerto remoto es sospechoso
                            if remote_port in suspicious_ports:
                                suspicious_connections.append({
                                    "protocol": protocol,
                                    "local_address": local_address,
                                    "remote_address": remote_address,
                                    "state": state,
                                    "pid": pid,
                                    "reason": f"Puerto sospechoso: {remote_port}"
                                })
            except Exception as e:
                print(
                    f"[!] Error al obtener conexiones de red en Windows: {e}")

        else:  # Linux/Unix
            try:
                output = subprocess.check_output(
                    ["netstat", "-tuln"], universal_newlines=True)
                # Saltar las primeras líneas (encabezado)
                for line in output.split('\n')[2:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5 and ("tcp" in parts[0] or "udp" in parts[0]):
                            protocol = parts[0]
                            local_address = parts[3]
                            state = parts[5] if len(parts) >= 6 else "N/A"

                            # Extraer puerto local
                            local_port = int(
                                local_address.split(':')[-1]) if ':' in local_address else 0

                            # Verificar si el puerto local es sospechoso
                            if local_port in suspicious_ports:
                                suspicious_connections.append({
                                    "protocol": protocol,
                                    "local_address": local_address,
                                    "state": state,
                                    "reason": f"Puerto sospechoso: {local_port}"
                                })
            except Exception as e:
                print(
                    f"[!] Error al obtener conexiones de red en Linux/Unix: {e}")

        return suspicious_connections

    except Exception as e:
        print(f"[!] Error al buscar conexiones sospechosas: {e}")
        return []


def run_backdoor_detection(target, voice_enabled=False):
    """
    Ejecuta una detección de backdoors y rootkits

    Args:
        target (str): Dirección IP o sistema objetivo
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados de la detección
    """
    try:
        print(f"\n===== INICIANDO DETECCIÓN DE BACKDOORS Y ROOTKITS =====\n")
        speak_text("Iniciando detección de backdoors y rootkits", voice_enabled)

        # Inicializar resultados
        results = {
            "target": target,
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

        # Verificar procesos sospechosos
        suspicious_processes = check_suspicious_processes(voice_enabled)
        if suspicious_processes:
            results["findings"].append({
                "type": "suspicious_processes",
                "description": BACKDOOR_PATTERNS["suspicious_processes"]["description"],
                "severity": BACKDOOR_PATTERNS["suspicious_processes"]["severity"],
                "recommendation": BACKDOOR_PATTERNS["suspicious_processes"]["recommendation"],
                "details": suspicious_processes
            })
            results["severity_counts"][BACKDOOR_PATTERNS["suspicious_processes"]
                                       ["severity"]] += 1
            results["total_findings"] += 1

        # Verificar conexiones sospechosas
        suspicious_connections = check_suspicious_connections(voice_enabled)
        if suspicious_connections:
            results["findings"].append({
                "type": "suspicious_network_connections",
                "description": BACKDOOR_PATTERNS["suspicious_network_connections"]["description"],
                "severity": BACKDOOR_PATTERNS["suspicious_network_connections"]["severity"],
                "recommendation": BACKDOOR_PATTERNS["suspicious_network_connections"]["recommendation"],
                "details": suspicious_connections
            })
            results["severity_counts"][BACKDOOR_PATTERNS["suspicious_network_connections"]["severity"]] += 1
            results["total_findings"] += 1

        # Guardar resultados en archivo
        output_dir = "resultados_backdoor"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/backdoor_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)

        # Mostrar resumen
        print(
            f"\n[+] Detección completada. Se encontraron {results['total_findings']} hallazgos")
        print("Distribución por severidad:")
        for severity, count in results["severity_counts"].items():
            if count > 0:
                print(f"  - {severity}: {count}")

        print(f"[+] Resultados guardados en {filename}")
        speak_text(
            f"Detección completada. Se encontraron {results['total_findings']} hallazgos", voice_enabled)

        print("\n===== DETECCIÓN DE BACKDOORS Y ROOTKITS COMPLETADA =====\n")
        speak_text("Detección de backdoors y rootkits completada", voice_enabled)

        return results

    except Exception as e:
        print(f"[!] Error al ejecutar detección de backdoors: {e}")
        return None


# Función principal para pruebas
if __name__ == "__main__":
    run_backdoor_detection("localhost", False)