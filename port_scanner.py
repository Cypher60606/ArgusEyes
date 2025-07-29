#!/usr/bin/env python3

from scanners import exploit_integration
from scanners import osint_module
from analyzers import ssl_analyzer
from scanners import fuzzing_module
from scanners import iot_scanner
from utils.voice_utils import speak_text
import nmap
import sys
import json
import re
import time
import os
import argparse
import pyttsx3

from datetime import datetime
# Importar módulos adicionales
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def scan_ip(target_ip, scan_type='default', voice_enabled=True):
    """
    Escanea una dirección IP para detectar puertos abiertos, servicios, versiones y vulnerabilidades.

    Args:
        target_ip (str): La dirección IP a escanear
        scan_type (str): Tipo de escaneo a realizar
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del escaneo
    """
    try:
        # Inicializar el escáner nmap
        nm = nmap.PortScanner()

        # Realizar un escaneo según el tipo seleccionado
        print(f"\n[*] Iniciando escaneo de {target_ip}...")
        print("[*] Este proceso puede tardar varios minutos...\n")

        # Anunciar inicio de escaneo con voz
        speak_text(
            f"Iniciando escaneo de la dirección IP {target_ip}", voice_enabled)

        # Definir argumentos según el tipo de escaneo
        scan_args = {
            'default': '-sS -sV -sC -Pn --open',
            'rapido': '-T4 -F -Pn --open',
            'sigiloso': '-sS -T2 -Pn --open',
            'completo': '-sS -sV -sC -A -T4 -Pn --open',
            'udp': '-sU -sV --open --top-ports 100',
            'detallado': '-sS -sV -sC -A -T4 -p- -Pn --open',
            'vuln': '-sV --script vuln -Pn --open'
        }

        # Verificar si el tipo de escaneo es válido
        if scan_type not in scan_args:
            print(
                f"\n[!] Tipo de escaneo '{scan_type}' no válido. Usando 'default'.")
            scan_type = 'default'

        # Ejecutar el escaneo
        nm.scan(hosts=target_ip, arguments=scan_args[scan_type])

        # Verificar si la IP está en los resultados
        if target_ip not in nm.all_hosts():
            print(
                f"\n[!] No se pudo escanear {target_ip}. Verifica la conexión o los permisos.")
            speak_text(
                f"No se pudo escanear la dirección IP {target_ip}. Verifica la conexión o los permisos.", voice_enabled)
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
        print(f"\n===== RESULTADOS DEL ESCANEO DE {target_ip} =====\n")
        print(f"IP: {target_ip}")
        print(f"Tipo de escaneo: {scan_type}")
        print(f"Puertos abiertos: {scan_results['total_puertos_abiertos']}")

        # Anunciar resultados básicos con voz
        speak_text(
            f"Escaneo completado. Se encontraron {scan_results['total_puertos_abiertos']} puertos abiertos en la dirección IP {target_ip}", voice_enabled)

        # Mostrar detalles de puertos
        if scan_results["total_puertos_abiertos"] > 0:
            print("\nDETALLES DE PUERTOS:")
            for puerto in scan_results["puertos"]:
                print(
                    f"\nPuerto: {puerto['puerto']}/{puerto['protocolo']} - {puerto['estado']}")
                print(f"Servicio: {puerto['servicio']}")
                if puerto["producto"]:
                    print(
                        f"Producto: {puerto['producto']} {puerto['version']} {puerto['extra_info']}")

                # Mostrar resultados de scripts si existen
                if puerto["scripts"]:
                    print("\nResultados de scripts:")
                    for script_name, result in puerto["scripts"].items():
                        print(f"  {script_name}: {result}")

         # Exportar resultados a archivo JSON
        export_scan_results(scan_results, target_ip, voice_enabled)

        return scan_results

    except Exception as e:
        print(f"\n[!] Error durante el escaneo: {e}")
        speak_text(f"Error durante el escaneo: {e}", voice_enabled)
        return {}


def export_scan_results(scan_results, target_ip, voice_enabled=True):
    """
    Exporta los resultados del escaneo a un archivo JSON

    Args:
        scan_results (dict): Resultados del escaneo
        target_ip (str): Dirección IP escaneada
        voice_enabled (bool): Indica si el asistente de voz está habilitado
    """
    try:
        # Crear directorio de resultados si no existe
        results_dir = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "resultados_escaneo")
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"escaneo_{target_ip.replace('.', '_')}_{timestamp}.json"
        filepath = os.path.join(results_dir, filename)

        # Guardar resultados en formato JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=4, ensure_ascii=False)

        print(f"\n[*] Resultados guardados en: {filepath}")
        speak_text(
            "Los resultados del escaneo han sido guardados en un archivo JSON", voice_enabled)

    except Exception as e:
        print(f"\n[!] Error al exportar resultados: {e}")


def export_results(scan_results, output_file, voice_enabled=True):
    """
    Exporta los resultados del escaneo a un archivo especificado por el usuario

    Args:
        scan_results (dict): Resultados del escaneo
        output_file (str): Ruta del archivo de salida
        voice_enabled (bool): Indica si el asistente de voz está habilitado
    """

    try:
        # Crear directorio de resultados si no existe
        results_dir = os.path.dirname(output_file)
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        # Guardar resultados en formato JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=4, ensure_ascii=False)

        print(f"\n[*] Resultados guardados en: {output_file}")
        speak_text(
            "Los resultados del escaneo han sido guardados en un archivo", voice_enabled)
    except Exception as e:
        print(f"\n[!] Error al exportar resultados: {e}")


def export_vuln_results(vuln_results, target_ip, voice_enabled=True):
    """Exporta los resultados del análisis de vulnerabilidades a un archivo JSON"""
    try:
        # Crear directorio de resultados si no existe
        results_dir = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "resultados_analisis")
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilidades_{target_ip.replace('.', '_')}_{timestamp}.json"
        filepath = os.path.join(results_dir, filename)

        # Guardar resultados en formato JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(vuln_results, f, indent=4, ensure_ascii=False)

        print(f"\n[*] Resultados de vulnerabilidades guardados en: {filepath}")
        speak_text(
            "Los resultados del análisis de vulnerabilidades han sido guardados en un archivo JSON", voice_enabled)
    except Exception as e:
        print(f"\n[!] Error al exportar resultados: {e}")


def analyze_vulnerabilities(scan_results, target_ip, voice_enabled=True):
    """
    Analiza vulnerabilidades basadas en los resultados del escaneo

    Args:
        scan_results (dict): Resultados del escaneo
        target_ip (str): Dirección IP escaneada
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del análisis de vulnerabilidades
    """
    try:
        print("\n[*] Analizando vulnerabilidades potenciales...")
        speak_text(
            "Analizando vulnerabilidades potenciales basadas en los servicios detectados", voice_enabled)

        # Inicializar diccionario de resultados
        vuln_results = {
            "target": target_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilidades": [],
            "total_vulnerabilidades": 0
        }

        # Analizar cada puerto y servicio
        for puerto in scan_results.get("puertos", []):
            servicio = puerto.get("servicio", "")
            version = puerto.get("version", "")
            producto = puerto.get("producto", "")
            puerto_num = puerto.get("puerto", 0)

            # Verificar vulnerabilidades conocidas por servicio
            vulns = check_service_vulnerabilities(
                servicio, version, producto, puerto_num)
            if vulns:
                for vuln in vulns:
                    vuln_results["vulnerabilidades"].append(vuln)
                    vuln_results["total_vulnerabilidades"] += 1

        # Mostrar resultados
        if vuln_results["total_vulnerabilidades"] > 0:
            print(
                f"\n[!] Se encontraron {vuln_results['total_vulnerabilidades']} vulnerabilidades potenciales")
            speak_text(
                f"Se encontraron {vuln_results['total_vulnerabilidades']} vulnerabilidades potenciales", voice_enabled)

            for vuln in vuln_results["vulnerabilidades"]:
                print(f"\n[VULNERABILIDAD] {vuln['nombre']}")
                print(f"Severidad: {vuln['severidad']}")
                print(f"Descripción: {vuln['descripcion']}")
                print(f"Afecta a: {vuln['servicio']} {vuln['version']}")
                if vuln.get("mitigacion"):
                    print(f"Mitigación: {vuln['mitigacion']}")
                if vuln.get("referencias"):
                    print("Referencias:")
                    for ref in vuln["referencias"]:
                        print(f"  - {ref}")
        else:
            print("\n[*] No se encontraron vulnerabilidades conocidas")
            speak_text(
                "No se encontraron vulnerabilidades conocidas en los servicios detectados", voice_enabled)

        # Exportar resultados
        if vuln_results["total_vulnerabilidades"] > 0:
            export_vuln_results(vuln_results, target_ip, voice_enabled)

        return vuln_results

    except Exception as e:
        print(f"\n[!] Error durante el análisis de vulnerabilidades: {e}")
        speak_text(
            f"Error durante el análisis de vulnerabilidades: {e}", voice_enabled)
        return {"vulnerabilidades": [], "total_vulnerabilidades": 0}


def check_service_vulnerabilities(servicio, version, producto, puerto):
    """Verifica vulnerabilidades conocidas para un servicio específico"""
    vulnerabilidades = []

    # Base de datos simple de vulnerabilidades conocidas
    # En una implementación real, esto podría conectarse a una base de datos CVE
    if servicio == "http" or servicio == "https":
        if "Apache" in producto:
            if version and version.startswith("2.4."):
                try:
                    version_num = int(version.split(".")[2])
                    if version_num < 50:
                        vulnerabilidades.append({
                            "nombre": "Apache HTTP Server - Vulnerabilidad de divulgación de información",
                            "severidad": "Media",
                            "descripcion": "Versiones de Apache HTTP Server anteriores a 2.4.50 son vulnerables a divulgación de información.",
                            "servicio": f"Apache {version}",
                            "version": version,
                            "puerto": puerto,
                            "mitigacion": "Actualizar a Apache 2.4.50 o superior",
                            "referencias": ["CVE-2021-41773", "https://httpd.apache.org/security/vulnerabilities_24.html"]
                        })
                except (IndexError, ValueError):
                    # Si la versión no tiene el formato esperado, continuamos sin añadir vulnerabilidad
                    pass
        elif "nginx" in producto.lower():
            if version and version.startswith("1.18."):
                vulnerabilidades.append({
                    "nombre": "Nginx - Posible DoS en procesamiento de solicitudes HTTP/2",
                    "severidad": "Baja",
                    "descripcion": "Algunas versiones de Nginx pueden ser vulnerables a ataques de denegación de servicio.",
                    "servicio": f"Nginx {version}",
                    "version": version,
                    "puerto": puerto,
                    "mitigacion": "Actualizar a la última versión estable",
                    "referencias": ["https://nginx.org/en/security_advisories.html"]
                })

    elif servicio == "ssh":
        if "OpenSSH" in producto:
            if version and version.startswith("7."):
                try:
                    version_num = int(version.split(".")[1])
                    if version_num < 9:
                        vulnerabilidades.append({
                            "nombre": "OpenSSH - Vulnerabilidad de autenticación",
                            "severidad": "Alta",
                            "descripcion": "Versiones antiguas de OpenSSH pueden permitir ataques de fuerza bruta o tener problemas de autenticación.",
                            "servicio": f"OpenSSH {version}",
                            "version": version,
                            "puerto": puerto,
                            "mitigacion": "Actualizar a OpenSSH 7.9 o superior, implementar fail2ban",
                            "referencias": ["https://www.openssh.com/security.html"]
                        })
                except (IndexError, ValueError):
                    # Si la versión no tiene el formato esperado, continuamos sin añadir vulnerabilidad
                    pass

    elif servicio == "ftp":
        vulnerabilidades.append({
            "nombre": "Servicio FTP - Transmisión de credenciales en texto plano",
            "severidad": "Alta",
            "descripcion": "El protocolo FTP transmite credenciales en texto plano, lo que puede permitir la interceptación de contraseñas.",
            "servicio": f"FTP {producto} {version}",
            "version": version,
            "puerto": puerto,
            "mitigacion": "Migrar a SFTP o FTPS para cifrar las comunicaciones",
            "referencias": ["https://owasp.org/www-community/vulnerabilities/FTP_Credential_Logging"]
        })

    elif servicio == "telnet":
        vulnerabilidades.append({
            "nombre": "Telnet - Protocolo inseguro",
            "severidad": "Crítica",
            "descripcion": "Telnet transmite toda la información, incluidas las credenciales, en texto plano.",
            "servicio": "Telnet",
            "version": version,
            "puerto": puerto,
            "mitigacion": "Deshabilitar Telnet y migrar a SSH",
            "referencias": ["https://owasp.org/www-community/vulnerabilities/Telnet_Protocol_Design_Flaws"]
        })

    # Verificar puertos comúnmente mal configurados
    if puerto == 3306:  # MySQL
        vulnerabilidades.append({
            "nombre": "MySQL expuesto a Internet",
            "severidad": "Alta",
            "descripcion": "El servidor MySQL está expuesto directamente a Internet, lo que puede permitir ataques de fuerza bruta.",
            "servicio": f"MySQL {version}",
            "version": version,
            "puerto": puerto,
            "mitigacion": "Restringir el acceso mediante firewall, usar VPN o SSH tunneling",
            "referencias": ["https://dev.mysql.com/doc/refman/8.0/en/security.html"]
        })

    elif puerto == 5432:  # PostgreSQL
        vulnerabilidades.append({
            "nombre": "PostgreSQL expuesto a Internet",
            "severidad": "Alta",
            "descripcion": "El servidor PostgreSQL está expuesto directamente a Internet.",
            "servicio": f"PostgreSQL {version}",
            "version": version,
            "puerto": puerto,
            "mitigacion": "Restringir el acceso mediante firewall, usar VPN o SSH tunneling",
            "referencias": ["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"]
        })

    return vulnerabilidades


def display_results(scan_results, voice_enabled=True):
    """Muestra los resultados del escaneo de forma detallada"""
    if not scan_results or "target" not in scan_results:
        print("\n[!] No hay resultados para mostrar")
        return

    target_ip = scan_results["target"]
    total_ports = scan_results["total_puertos_abiertos"]

    print(f"\n===== INFORME DETALLADO DE {target_ip} =====\n")
    print(f"IP: {target_ip}")
    print(f"Tipo de escaneo: {scan_results.get('scan_type', 'desconocido')}")
    print(f"Fecha y hora: {scan_results.get('timestamp', 'desconocido')}")
    print(f"Puertos abiertos: {total_ports}")

    # Mostrar detalles de puertos
    if total_ports > 0:
        print("\nDETALLES DE PUERTOS:")
        for puerto in scan_results["puertos"]:
            print(
                f"\nPuerto: {puerto['puerto']}/{puerto['protocolo']} - {puerto['estado']}")
            print(f"Servicio: {puerto['servicio']}")
            if puerto["producto"]:
                print(f"Producto: {puerto['producto']}")
            if puerto["version"]:
                print(f"Versión: {puerto['version']}")
            if puerto["extra_info"]:
                print(f"Información adicional: {puerto['extra_info']}")

            if puerto["scripts"]:
                print("\nResultados de scripts:")
                for script_name, result in puerto["scripts"].items():
                    print(f"  {script_name}: {result[:100]}..." if len(
                        result) > 100 else f"  {script_name}: {result}")

    # Anunciar resumen con voz
    speak_text(
        f"Se ha generado un informe detallado del escaneo. Se encontraron {total_ports} puertos abiertos en {target_ip}", voice_enabled)


# Función principal para ejecutar el escáner desde línea de comandos
def main():
    # Configurar el parser de argumentos
    parser = argparse.ArgumentParser(
        description='Escáner de Puertos y Vulnerabilidades con Asistente de Voz',
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Argumentos generales
    parser.add_argument('target', help='Dirección IP o dominio a escanear')
    parser.add_argument('-t', '--type', choices=['default', 'rapido', 'sigiloso', 'completo', 'udp', 'detallado', 'vuln'],
                        default='default', help='Tipo de escaneo a realizar')
    parser.add_argument('-v', '--voice', action='store_true',
                        help='Habilitar asistente de voz')
    parser.add_argument('-o', '--output', help='Guardar resultados en archivo')

    # Argumentos específicos para cada tipo de escaneo
    parser.add_argument('--vuln', action='store_true',
                        help='Realizar análisis de vulnerabilidades')
    parser.add_argument('--iot', action='store_true',
                        help='Realizar escaneo específico de dispositivos IoT')
    parser.add_argument('--fuzzing', action='store_true',
                        help='Realizar fuzzing de directorios y archivos web')
    parser.add_argument('--osint', action='store_true',
                        help='Realizar recolección de información OSINT')

    args = parser.parse_args()

    # Mensaje de bienvenida
    print("\n===== ESCÁNER DE PUERTOS Y VULNERABILIDADES =====\n")
    speak_text("Iniciando escáner de puertos y vulnerabilidades", args.voice)

    # Ejecutar el tipo de escaneo seleccionado
    if args.iot:
        print("[*] Iniciando escaneo de dispositivos IoT...")
        speak_text("Iniciando escaneo de dispositivos IoT", args.voice)
        results = iot_scanner.run_iot_scan(args.target, args.type, args.voice)
    elif args.fuzzing:
        print("[*] Iniciando fuzzing de directorios web...")
        speak_text("Iniciando fuzzing de directorios web", args.voice)
        results = fuzzing_module.run_fuzzing_scan(args.target, args.voice)
    elif args.osint:
        print("[*] Iniciando recolección de información OSINT...")
        speak_text("Iniciando recolección de información OSINT", args.voice)
        results = osint_module.run_osint_analysis(args.target, args.voice)
    else:
        # Escaneo estándar de puertos
        results = scan_ip(args.target, args.type, args.voice)

    # Realizar análisis de vulnerabilidades si se solicita
    if args.vuln and results and "puertos" in results:
        vuln_results = analyze_vulnerabilities(
            results, args.target, args.voice)

    # Mostrar resultados detallados
    if results and "puertos" in results:
        display_results(results, args.voice)

    # Exportar resultados si se especificó un archivo de salida
    if args.output and results:
        export_results(results, args.output, args.voice)

    print("\n===== ESCANEO COMPLETADO =====\n")
    speak_text("Escaneo completado", args.voice)


if __name__ == "__main__":
    main()