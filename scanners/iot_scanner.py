#!/usr/bin/env python3


import nmap
import json
import re
import os
import sys
import time
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.voice_utils import speak_text

# Diccionario de dispositivos IoT comunes y sus características
IOT_DEVICES = {
    "camaras": {
        "puertos": [80, 443, 554, 1935, 8000, 8080, 8443, 9000],
        "servicios": ["rtsp", "http", "https", "hikvision", "dahua", "axis", "onvif"],
        "fabricantes": ["Hikvision", "Dahua", "Axis", "Foscam", "Nest", "Ring", "Arlo", "Wyze"]
    },
    "routers": {
        "puertos": [80, 443, 22, 23, 53, 8080, 8443],
        "servicios": ["http", "https", "ssh", "telnet", "dns"],
        "fabricantes": ["Cisco", "Linksys", "TP-Link", "D-Link", "Netgear", "Huawei", "MikroTik"]
    },
    "termostatos": {
        "puertos": [80, 443, 8080, 1883, 8883],
        "servicios": ["http", "https", "mqtt"],
        "fabricantes": ["Nest", "Ecobee", "Honeywell", "Emerson"]
    },
    "asistentes_voz": {
        "puertos": [80, 443, 8080, 1883, 8883],
        "servicios": ["http", "https", "mqtt"],
        "fabricantes": ["Amazon", "Google", "Apple", "Microsoft"]
    },
    "bombillas": {
        "puertos": [80, 443, 1883, 8883, 5683, 5684],
        "servicios": ["http", "https", "mqtt", "coap"],
        "fabricantes": ["Philips Hue", "LIFX", "TP-Link", "Wyze", "Sengled"]
    },
    "cerraduras": {
        "puertos": [80, 443, 1883, 8883, 5683, 5684],
        "servicios": ["http", "https", "mqtt", "coap", "zwave", "zigbee"],
        "fabricantes": ["August", "Schlage", "Yale", "Kwikset", "Lockly"]
    },
    "electrodomesticos": {
        "puertos": [80, 443, 1883, 8883],
        "servicios": ["http", "https", "mqtt"],
        "fabricantes": ["Samsung", "LG", "Whirlpool", "GE", "Bosch"]
    }
}

# Vulnerabilidades comunes en dispositivos IoT
IOT_VULNERABILITIES = {
    "default_credentials": {
        "descripcion": "Credenciales por defecto o débiles",
        "impacto": "ALTO",
        "recomendacion": "Cambiar todas las contraseñas por defecto y utilizar contraseñas fuertes y únicas"
    },
    "open_telnet": {
        "descripcion": "Servicio Telnet abierto",
        "impacto": "ALTO",
        "recomendacion": "Deshabilitar Telnet y utilizar SSH con autenticación por clave"
    },
    "outdated_firmware": {
        "descripcion": "Firmware desactualizado",
        "impacto": "ALTO",
        "recomendacion": "Actualizar el firmware a la última versión disponible"
    },
    "insecure_web_interface": {
        "descripcion": "Interfaz web insegura",
        "impacto": "MEDIO",
        "recomendacion": "Implementar HTTPS, autenticación segura y protección contra ataques web"
    },
    "weak_encryption": {
        "descripcion": "Cifrado débil o inexistente",
        "impacto": "ALTO",
        "recomendacion": "Implementar cifrado fuerte para todas las comunicaciones"
    },
    "data_exposure": {
        "descripcion": "Exposición de datos sensibles",
        "impacto": "ALTO",
        "recomendacion": "Cifrar datos en reposo y en tránsito, implementar controles de acceso"
    },
    "upnp_enabled": {
        "descripcion": "UPnP habilitado",
        "impacto": "MEDIO",
        "recomendacion": "Deshabilitar UPnP si no es necesario o restringir su alcance"
    },
    "no_updates": {
        "descripcion": "Sin mecanismo de actualización",
        "impacto": "MEDIO",
        "recomendacion": "Considerar reemplazar dispositivos sin soporte de actualizaciones"
    },
    "hardcoded_secrets": {
        "descripcion": "Secretos codificados en firmware",
        "impacto": "CRÍTICO",
        "recomendacion": "Actualizar firmware o reemplazar dispositivo si no hay solución"
    }
}


def scan_iot_devices(target_ip, scan_type='default', voice_enabled=True):
    """
    Escanea dispositivos IoT en la red

    Args:
        target_ip (str): La dirección IP a escanear
        scan_type (str): Tipo de escaneo a realizar
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del escaneo
    """
    try:
        print(f"\n[*] Iniciando escaneo de dispositivos IoT en {target_ip}...")
        speak_text(f"Iniciando escaneo de dispositivos IoT en {target_ip}", voice_enabled)

        # Inicializar el escáner nmap
        nm = nmap.PortScanner()

        # Definir argumentos según el tipo de escaneo
        scan_args = {
            'default': '-sS -sV -Pn --open',
            'rapido': '-T4 -F -Pn --open',
            'completo': '-sS -sV -sC -A -T4 -Pn --open',
            'iot': '-sS -sV -p 80,443,22,23,25,8080,8443,1883,8883,5683,5684,502,102,53,123,161,554,1935,9000 -Pn --open'
        }

        # Verificar si el tipo de escaneo es válido
        if scan_type not in scan_args:
            print(f"\n[!] Tipo de escaneo '{scan_type}' no válido para IoT. Usando 'iot'.")
            scan_type = 'iot'

        # Ejecutar el escaneo
        print("[*] Escaneando puertos y servicios comunes en dispositivos IoT...")
        nm.scan(hosts=target_ip, arguments=scan_args[scan_type])

        # Verificar si la IP está en los resultados
        if target_ip not in nm.all_hosts():
            print(f"\n[!] No se pudo escanear {target_ip}. Verifica la conexión o los permisos.")
            speak_text(f"No se pudo escanear la dirección IP {target_ip}. Verifica la conexión o los permisos.", voice_enabled)
            return {}

        # Inicializar diccionario de resultados
        scan_results = {
            "target": target_ip,
            "scan_type": scan_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_puertos_abiertos": 0,
            "puertos": []
        }

        # Procesar resultados
        for proto in nm[target_ip].all_protocols():
            lport = sorted(nm[target_ip][proto].keys())
            scan_results["total_puertos_abiertos"] += len(lport)

            for port in lport:
                port_info = nm[target_ip][proto][port]
                puerto_data = {
                    "puerto": port,
                    "protocolo": proto,
                    "estado": port_info.get("state", "desconocido"),
                    "servicio": port_info.get("name", "desconocido"),
                    "producto": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extra_info": port_info.get("extrainfo", ""),
                    "scripts": {}
                }

                # Extraer resultados de scripts
                if 'script' in port_info:
                    puerto_data["scripts"] = port_info["script"]

                scan_results["puertos"].append(puerto_data)

        # Mostrar resultados básicos
        print(f"\n[*] Escaneo de dispositivos IoT completado en {target_ip}")
        print(f"[*] Puertos abiertos: {scan_results['total_puertos_abiertos']}")

        return scan_results

    except Exception as e:
        print(f"\n[!] Error durante el escaneo de dispositivos IoT: {e}")
        speak_text(f"Error durante el escaneo de dispositivos IoT: {e}", voice_enabled)
        return {}


def identify_iot_devices(scan_results, target_ip):
    """
    Identifica dispositivos IoT basados en los resultados del escaneo

    Args:
        scan_results (dict): Resultados del escaneo
        target_ip (str): Dirección IP escaneada

    Returns:
        dict: Información de dispositivos IoT identificados
    """
    try:
        print("\n[*] Analizando resultados para identificar dispositivos IoT...")

        # Inicializar diccionario de resultados
        iot_results = {
            "target": target_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dispositivos_detectados": [],
            "possible_vulnerabilities": []
        }

        # Verificar si hay puertos abiertos
        if not scan_results or "puertos" not in scan_results or not scan_results["puertos"]:
            print("\n[!] No hay puertos abiertos para analizar dispositivos IoT")
            return {}

        # Recopilar información de puertos y servicios
        puertos_abiertos = [p["puerto"] for p in scan_results["puertos"]]
        servicios_detectados = [p["servicio"].lower() for p in scan_results["puertos"]]
        productos_detectados = [p["producto"].lower() for p in scan_results["puertos"] if p["producto"]]

        # Buscar coincidencias con dispositivos IoT conocidos
        for device_type, device_info in IOT_DEVICES.items():
            # Verificar coincidencias de puertos
            puertos_coincidentes = [p for p in puertos_abiertos if p in device_info["puertos"]]
            # Verificar coincidencias de servicios
            servicios_coincidentes = [s for s in servicios_detectados if any(iot_s in s for iot_s in device_info["servicios"])]
            # Verificar coincidencias de fabricantes
            fabricantes_coincidentes = []
            for producto in productos_detectados:
                for fabricante in device_info["fabricantes"]:
                    if fabricante.lower() in producto:
                        fabricantes_coincidentes.append(fabricante)

            # Calcular puntuación de coincidencia
            match_score = len(puertos_coincidentes) * 1 + len(servicios_coincidentes) * 2 + len(fabricantes_coincidentes) * 3

            # Si hay suficiente coincidencia, añadir a los resultados
            if match_score >= 2 or len(fabricantes_coincidentes) > 0:
                device_match = {
                    "tipo": device_type,
                    "confianza": min(match_score * 10, 100),  # Porcentaje de confianza, máximo 100%
                    "puertos_coincidentes": puertos_coincidentes,
                    "servicios_coincidentes": servicios_coincidentes,
                    "fabricantes_detectados": fabricantes_coincidentes
                }
                iot_results["dispositivos_detectados"].append(device_match)

                # Buscar posibles vulnerabilidades basadas en el tipo de dispositivo y servicios
                for puerto in scan_results["puertos"]:
                    # Verificar vulnerabilidades comunes
                    if puerto["servicio"] == "telnet" and puerto["estado"] == "open":
                        iot_results["possible_vulnerabilities"].append({
                            "tipo": "open_telnet",
                            "puerto": puerto["puerto"],
                            "descripcion": IOT_VULNERABILITIES["open_telnet"]["descripcion"],
                            "impacto": IOT_VULNERABILITIES["open_telnet"]["impacto"],
                            "recomendacion": IOT_VULNERABILITIES["open_telnet"]["recomendacion"]
                        })

                    # Verificar servicios web sin HTTPS
                    if puerto["servicio"] == "http" and puerto["puerto"] not in [443, 8443]:
                        iot_results["possible_vulnerabilities"].append({
                            "tipo": "insecure_web_interface",
                            "puerto": puerto["puerto"],
                            "descripcion": IOT_VULNERABILITIES["insecure_web_interface"]["descripcion"],
                            "impacto": IOT_VULNERABILITIES["insecure_web_interface"]["impacto"],
                            "recomendacion": IOT_VULNERABILITIES["insecure_web_interface"]["recomendacion"]
                        })

                    # Verificar UPnP
                    if puerto["servicio"] == "upnp" or puerto["puerto"] == 1900:
                        iot_results["possible_vulnerabilities"].append({
                            "tipo": "upnp_enabled",
                            "puerto": puerto["puerto"],
                            "descripcion": IOT_VULNERABILITIES["upnp_enabled"]["descripcion"],
                            "impacto": IOT_VULNERABILITIES["upnp_enabled"]["impacto"],
                            "recomendacion": IOT_VULNERABILITIES["upnp_enabled"]["recomendacion"]
                        })

                    # Verificar versiones antiguas o conocidas como vulnerables
                    if puerto["version"] and any(v in puerto["version"].lower() for v in ["1.0", "2.0", "old", "legacy", "vulnerable"]):
                        iot_results["possible_vulnerabilities"].append({
                            "tipo": "outdated_firmware",
                            "puerto": puerto["puerto"],
                            "servicio": puerto["servicio"],
                            "version": puerto["version"],
                            "descripcion": IOT_VULNERABILITIES["outdated_firmware"]["descripcion"],
                            "impacto": IOT_VULNERABILITIES["outdated_firmware"]["impacto"],
                            "recomendacion": IOT_VULNERABILITIES["outdated_firmware"]["recomendacion"]
                        })

        # Mostrar resultados
        if iot_results["dispositivos_detectados"]:
            print(f"\n[*] Se detectaron {len(iot_results['dispositivos_detectados'])} posibles dispositivos IoT:")
            for device in iot_results["dispositivos_detectados"]:
                print(f"  - Tipo: {device['tipo']} (Confianza: {device['confianza']}%)")
                if device["fabricantes_detectados"]:
                    print(f"    Fabricante: {', '.join(device['fabricantes_detectados'])}")

            if iot_results["possible_vulnerabilities"]:
                print(f"\n[*] Se detectaron {len(iot_results['possible_vulnerabilities'])} posibles vulnerabilidades:")
                for vuln in iot_results["possible_vulnerabilities"]:
                    print(f"  - {vuln['tipo']}: {vuln['descripcion']} (Impacto: {vuln['impacto']})")
        else:
            print("\n[!] No se detectaron dispositivos IoT con suficiente confianza")

        return iot_results

    except Exception as e:
        print(f"\n[!] Error al identificar dispositivos IoT: {e}")
        return {}


def run_iot_scan(target_ip, scan_type='default', voice_enabled=True, analyze_attack_chains=True):
    """
    Ejecuta un escaneo completo de dispositivos IoT y analiza posibles cadenas de ataque

    Args:
        target_ip (str): La dirección IP a escanear
        scan_type (str): Tipo de escaneo a realizar
        voice_enabled (bool): Indica si el asistente de voz está habilitado
        analyze_attack_chains (bool): Indica si se debe realizar análisis de cadenas de ataque

    Returns:
        dict: Resultados del análisis de dispositivos IoT
    """
    try:
        # Realizar escaneo de puertos y servicios
        scan_results = scan_iot_devices(target_ip, scan_type, voice_enabled)
        if not scan_results:
            return {}

        # Identificar dispositivos IoT y sus vulnerabilidades
        iot_devices = identify_iot_devices(scan_results, target_ip)
        
        # Si no se encontraron dispositivos, terminar
        if not iot_devices:
            print(f"\n[!] No se detectaron dispositivos IoT en {target_ip}")
            return {}
            
        # Mostrar resultados de dispositivos IoT
        # Aquí iría la función display_iot_results que debe implementarse
        
        # Exportar resultados básicos
        # Aquí iría la función export_iot_results que debe implementarse
        
        # Analizar cadenas de ataque si está habilitado y se encontraron vulnerabilidades
        if analyze_attack_chains and iot_devices.get("possible_vulnerabilities"):
            print("\n[*] Iniciando análisis de cadenas de ataque potenciales...")
            speak_text("Iniciando análisis de cadenas de ataque potenciales basadas en las vulnerabilidades detectadas.", voice_enabled)
            
            # Importar el módulo de correlación de vulnerabilidades
            try:
                from analyzers.vulnerability_correlation import analyze_attack_vectors
                # Realizar análisis de cadenas de ataque
                attack_chains = analyze_attack_vectors(iot_devices, target_ip, voice_enabled)
                # Añadir resultados de cadenas de ataque al diccionario de resultados
                iot_devices["attack_chains"] = attack_chains
            except ImportError as e:
                print(f"\n[!] Error al importar el módulo de correlación de vulnerabilidades: {e}")
                print("[!] Asegúrate de que el módulo existe en la carpeta 'analyzers'")
            except Exception as e:
                print(f"\n[!] Error al analizar cadenas de ataque: {e}")
        
        print("\n===== ANÁLISIS DE DISPOSITIVOS IOT COMPLETADO =====\n")
        return iot_devices

    except Exception as e:
        print(f"\n[!] Error al ejecutar el análisis de dispositivos IoT: {e}")
        return {}


# Función principal para pruebas independientes
if __name__ == "__main__":
    # Ejemplo de uso independiente
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        scan_type = sys.argv[2] if len(sys.argv) > 2 else 'default'
        run_iot_scan(target_ip, scan_type)
    else:
        print("\n[!] Uso: python iot_scanner.py <dirección_ip> [tipo_escaneo]")
