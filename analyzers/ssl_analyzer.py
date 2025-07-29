#!/usr/bin/env python3

from utils.voice_utils import speak_text
import subprocess
import re
import json
import os
import sys
import socket
import datetime
import ssl
import OpenSSL
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def analyze_ssl_certificate(target_ip, port, timeout=10, voice_enabled=True):
    """
    Analiza el certificado SSL/TLS de un servicio

    Args:
        target_ip (str): La dirección IP del objetivo
        port (int): El puerto del servicio
        timeout (int): Tiempo máximo de espera para la conexión en segundos
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Información del certificado SSL/TLS
    """
    try:
        print(f"\n[*] Analizando certificado SSL/TLS en {target_ip}:{port}...")

        # Crear contexto SSL
        context = ssl.create_default_context()
        context.check_hostname = False
        # No verificar el certificado para poder analizar incluso los inválidos
        context.verify_mode = ssl.CERT_NONE

        # Establecer conexión SSL
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                # Obtener certificado en formato binario
                cert_bin = ssock.getpeercert(binary_form=True)

                # Convertir a formato OpenSSL para análisis detallado
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1, cert_bin)

                # Extraer información del certificado
                cert_info = {
                    "subject": dict(x509.get_subject().get_components()),
                    "issuer": dict(x509.get_issuer().get_components()),
                    "version": x509.get_version(),
                    "serial_number": x509.get_serial_number(),
                    "not_before": x509.get_notBefore().decode('ascii'),
                    "not_after": x509.get_notAfter().decode('ascii'),
                    "has_expired": x509.has_expired(),
                    "signature_algorithm": x509.get_signature_algorithm().decode('ascii'),
                    "extensions": get_certificate_extensions(x509),
                    "public_key_bits": x509.get_pubkey().bits(),
                    "public_key_type": get_public_key_type(x509.get_pubkey().type())
                }

                # Convertir bytes a strings en subject e issuer
                for key in ['subject', 'issuer']:
                    cert_info[key] = {k.decode('utf-8'): v.decode('utf-8')
                                      for k, v in cert_info[key].items()}

                # Verificar fecha de expiración
                not_after = datetime.strptime(
                    cert_info['not_after'], '%Y%m%d%H%M%SZ')
                now = datetime.now()
                days_to_expire = (not_after - now).days
                cert_info['days_to_expire'] = days_to_expire

                # Obtener información de la conexión SSL
                cert_info['protocol_version'] = ssock.version()
                cert_info['cipher'] = ssock.cipher()

                return cert_info

    except ssl.SSLError as e:
        print(f"\n[!] Error SSL: {e}")
        return {"error": f"Error SSL: {e}"}
    except socket.error as e:
        print(f"\n[!] Error de conexión: {e}")
        return {"error": f"Error de conexión: {e}"}
    except Exception as e:
        print(f"\n[!] Error al analizar certificado: {e}")
        return {"error": f"Error al analizar certificado: {e}"}


def get_certificate_extensions(x509):
    """
    Extrae las extensiones de un certificado X509

    Args:
        x509: Objeto certificado OpenSSL

    Returns:
        dict: Diccionario con las extensiones del certificado
    """
    extensions = {}
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        ext_name = ext.get_short_name().decode('utf-8')
        try:
            ext_value = str(ext)
            extensions[ext_name] = ext_value
        except:
            extensions[ext_name] = "<binary data>"
    return extensions


def get_public_key_type(key_type):
    """
    Convierte el tipo numérico de clave a texto

    Args:
        key_type: Tipo numérico de clave pública

    Returns:
        str: Tipo de clave en formato texto
    """
    key_types = {
        OpenSSL.crypto.TYPE_RSA: "RSA",
        OpenSSL.crypto.TYPE_DSA: "DSA",
        OpenSSL.crypto.TYPE_DH: "DH",
        OpenSSL.crypto.TYPE_EC: "EC"
    }
    return key_types.get(key_type, f"Unknown ({key_type})")


def analyze_ssl_configuration(target_ip, port, voice_enabled=True):
    """
    Analiza la configuración SSL/TLS de un servicio

    Args:
        target_ip (str): La dirección IP del objetivo
        port (int): El puerto del servicio
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados del análisis SSL/TLS
    """
    try:
        print(
            f"\n[*] Analizando configuración SSL/TLS en {target_ip}:{port}...")
        print("[*] Este proceso puede tardar varios minutos...\n")

        # Anunciar inicio de análisis con voz
        speak_text(
            f"Iniciando análisis de configuración SSL/TLS en {target_ip}:{port}", voice_enabled)

        # Obtener información del certificado
        cert_info = analyze_ssl_certificate(
            target_ip, port, voice_enabled=voice_enabled)

        # Analizar protocolos y cifrados soportados
        protocols = check_supported_protocols(target_ip, port)
        ciphers = check_supported_ciphers(target_ip, port)

        # Evaluar la seguridad de la configuración
        security_issues = evaluate_ssl_security(cert_info, protocols, ciphers)

        # Crear informe completo
        ssl_analysis = {
            "target": f"{target_ip}:{port}",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "certificate": cert_info,
            "protocols": protocols,
            "ciphers": ciphers,
            "security_issues": security_issues
        }

        # Guardar resultados
        save_ssl_analysis(ssl_analysis, target_ip, port)

        return ssl_analysis

    except Exception as e:
        print(f"\n[!] Error al analizar configuración SSL/TLS: {e}")
        return None


def check_supported_protocols(target_ip, port):
    """
    Verifica qué protocolos SSL/TLS son soportados

    Args:
        target_ip (str): La dirección IP del objetivo
        port (int): El puerto del servicio

    Returns:
        dict: Protocolos soportados y su estado
    """
    protocols = {
        "SSLv2": False,
        "SSLv3": False,
        "TLSv1.0": False,
        "TLSv1.1": False,
        "TLSv1.2": False,
        "TLSv1.3": False
    }

    # Intentar conexión con cada protocolo
    for protocol_name in protocols.keys():
        supported = test_protocol_support(target_ip, port, protocol_name)
        protocols[protocol_name] = supported

    return protocols


def test_protocol_support(target_ip, port, protocol_name):
    """
    Prueba si un protocolo específico es soportado

    Args:
        target_ip (str): La dirección IP del objetivo
        port (int): El puerto del servicio
        protocol_name (str): Nombre del protocolo a probar

    Returns:
        bool: True si el protocolo es soportado, False en caso contrario
    """
    # Mapeo de nombres de protocolo a constantes de SSL
    protocol_versions = {
        "SSLv2": ssl.PROTOCOL_SSLv23,  # No hay constante específica para SSLv2
        "SSLv3": ssl.PROTOCOL_SSLv23,  # No hay constante específica para SSLv3
        "TLSv1.0": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        "TLSv1.3": ssl.PROTOCOL_TLS  # En Python 3.7+, esto incluye TLS 1.3
    }

    try:
        # Crear contexto SSL con el protocolo específico
        if protocol_name in protocol_versions:
            context = ssl.SSLContext(protocol_versions[protocol_name])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Para SSLv2 y SSLv3, necesitamos configuraciones adicionales
            if protocol_name == "SSLv2" or protocol_name == "SSLv3":
                context.options &= ~ssl.OP_NO_SSLv2 & ~ssl.OP_NO_SSLv3

            # Intentar conexión
            with socket.create_connection((target_ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    # Si llegamos aquí, la conexión fue exitosa
                    return True
    except:
        pass

    return False


def check_supported_ciphers(target_ip, port):
    """
    Verifica qué cifrados SSL/TLS son soportados

    Args:
        target_ip (str): La dirección IP del objetivo
        port (int): El puerto del servicio

    Returns:
        list: Lista de cifrados soportados
    """
    # Esta función requiere nmap con scripts ssl-enum-ciphers
    # Usamos subprocess para ejecutar nmap y analizar su salida
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(target_ip, str(port), '--script ssl-enum-ciphers -Pn')

        ciphers = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                if port in nm[target_ip][proto]:
                    if 'script' in nm[target_ip][proto][port] and 'ssl-enum-ciphers' in nm[target_ip][proto][port]['script']:
                        # Extraer información de cifrados del resultado del script
                        cipher_output = nm[target_ip][proto][port]['script']['ssl-enum-ciphers']
                        # Parsear la salida para extraer los cifrados
                        for line in cipher_output.split('\n'):
                            if 'TLSv' in line or 'SSLv' in line:
                                protocol = line.strip()
                            if 'ciphers' in line:
                                continue
                            if '|' in line and 'TLS' not in line and 'SSL' not in line:
                                cipher_name = line.split('|')[1].strip() if len(
                                    line.split('|')) > 1 else line.strip()
                                if cipher_name and not cipher_name.startswith('|'):
                                    ciphers.append({
                                        "name": cipher_name,
                                        "protocol": protocol if 'protocol' in locals() else "Unknown"
                                    })

        return ciphers
    except Exception as e:
        print(f"Error al verificar cifrados: {e}")
        return []


def evaluate_ssl_security(cert_info, protocols, ciphers):
    """
    Evalúa la seguridad de la configuración SSL/TLS

    Args:
        cert_info (dict): Información del certificado
        protocols (dict): Protocolos soportados
        ciphers (list): Cifrados soportados

    Returns:
        list: Problemas de seguridad encontrados
    """
    issues = []

    # Verificar certificado expirado
    if cert_info.get('has_expired', False):
        issues.append({
            "severity": "ALTO",
            "issue": "Certificado expirado",
            "description": "El certificado SSL/TLS ha expirado y debe ser renovado."
        })
    elif cert_info.get('days_to_expire', 0) < 30:
        issues.append({
            "severity": "MEDIO",
            "issue": "Certificado próximo a expirar",
            "description": f"El certificado expirará en {cert_info.get('days_to_expire')} días."
        })

    # Verificar protocolos obsoletos
    if protocols.get("SSLv2", False):
        issues.append({
            "severity": "ALTO",
            "issue": "SSLv2 habilitado",
            "description": "SSLv2 es un protocolo obsoleto e inseguro que debe ser deshabilitado."
        })

    if protocols.get("SSLv3", False):
        issues.append({
            "severity": "ALTO",
            "issue": "SSLv3 habilitado",
            "description": "SSLv3 es vulnerable a POODLE y debe ser deshabilitado."
        })

    if protocols.get("TLSv1.0", False):
        issues.append({
            "severity": "MEDIO",
            "issue": "TLSv1.0 habilitado",
            "description": "TLSv1.0 es un protocolo antiguo con vulnerabilidades conocidas."
        })

    if protocols.get("TLSv1.1", False):
        issues.append({
            "severity": "BAJO",
            "issue": "TLSv1.1 habilitado",
            "description": "TLSv1.1 es un protocolo antiguo que está siendo deprecado."
        })

    # Verificar si TLS 1.2 o superior está habilitado
    if not protocols.get("TLSv1.2", False) and not protocols.get("TLSv1.3", False):
        issues.append({
            "severity": "ALTO",
            "issue": "Sin soporte para TLS 1.2 o superior",
            "description": "No se detectó soporte para TLS 1.2 o TLS 1.3, que son los protocolos recomendados."
        })

    # Verificar cifrados débiles
    weak_ciphers = ["NULL", "EXPORT", "DES", "RC4", "MD5", "anon"]
    detected_weak_ciphers = []

    for cipher in ciphers:
        cipher_name = cipher.get("name", "")
        for weak in weak_ciphers:
            if weak in cipher_name:
                detected_weak_ciphers.append(cipher_name)
                break

    if detected_weak_ciphers:
        issues.append({
            "severity": "ALTO",
            "issue": "Cifrados débiles detectados",
            "description": f"Se detectaron cifrados débiles o inseguros: {', '.join(detected_weak_ciphers[:5])}" +
            (" y otros..." if len(detected_weak_ciphers) > 5 else "")
        })

    # Verificar algoritmo de firma
    sig_alg = cert_info.get('signature_algorithm', '')
    if 'md5' in sig_alg.lower() or 'sha1' in sig_alg.lower():
        issues.append({
            "severity": "ALTO",
            "issue": "Algoritmo de firma débil",
            "description": f"El certificado utiliza un algoritmo de firma débil: {sig_alg}"
        })

    # Verificar tamaño de clave
    key_bits = cert_info.get('public_key_bits', 0)
    key_type = cert_info.get('public_key_type', '')

    if key_type == 'RSA' and key_bits < 2048:
        issues.append({
            "severity": "ALTO",
            "issue": "Clave RSA débil",
            "description": f"El certificado utiliza una clave RSA de {key_bits} bits, que es considerada débil. Se recomienda al menos 2048 bits."
        })
    elif key_type == 'EC' and key_bits < 256:
        issues.append({
            "severity": "ALTO",
            "issue": "Clave EC débil",
            "description": f"El certificado utiliza una clave EC de {key_bits} bits, que es considerada débil. Se recomienda al menos 256 bits."
        })

    return issues


def save_ssl_analysis(analysis, target_ip, port):
    """
    Guarda los resultados del análisis SSL/TLS en un archivo JSON

    Args:
        analysis (dict): Resultados del análisis
        target_ip (str): IP analizada
        port (int): Puerto analizado
    """
    # Crear directorio si no existe
    output_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "reports", "ssl_analysis")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generar nombre de archivo con timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ssl_analysis_{target_ip.replace('.', '_')}_{port}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    # Guardar resultados
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=4, ensure_ascii=False)

    print(f"\n[+] Resultados guardados en: {filepath}")
    return filepath


def display_ssl_analysis(analysis, target_ip, port, voice_enabled=True):
    """
    Muestra los resultados del análisis SSL/TLS

    Args:
        analysis (dict): Resultados del análisis
        target_ip (str): La dirección IP analizada
        port (int): El puerto analizado
        voice_enabled (bool): Indica si el asistente de voz está habilitado
    """
    if analysis is None:
        print("\n[!] No se pudo completar el análisis SSL/TLS.")
        return

    print(f"\n{'=' * 60}")
    print(f"RESULTADOS DEL ANÁLISIS SSL/TLS PARA: {target_ip}:{port}")
    print(f"{'=' * 60}\n")

    # Información del certificado
    cert_info = analysis.get('certificate', {})
    print("INFORMACIÓN DEL CERTIFICADO:")

    # Datos básicos
    if 'subject' in cert_info and 'CN' in cert_info['subject']:
        print(f"Nombre común (CN): {cert_info['subject']['CN']}")

    if 'issuer' in cert_info and 'CN' in cert_info['issuer']:
        print(f"Emisor: {cert_info['issuer']['CN']}")

    if 'not_before' in cert_info and 'not_after' in cert_info:
        not_before = datetime.strptime(
            cert_info['not_before'], '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert_info['not_after'], '%Y%m%d%H%M%SZ')
        print(f"Válido desde: {not_before.strftime('%Y-%m-%d')}")
        print(f"Válido hasta: {not_after.strftime('%Y-%m-%d')}")

    if 'days_to_expire' in cert_info:
        days = cert_info['days_to_expire']
        if days < 0:
            print(f"Estado: EXPIRADO (hace {abs(days)} días)")
        else:
            print(f"Estado: Válido (expira en {days} días)")

    if 'signature_algorithm' in cert_info:
        print(f"Algoritmo de firma: {cert_info['signature_algorithm']}")

    if 'public_key_bits' in cert_info and 'public_key_type' in cert_info:
        print(
            f"Clave pública: {cert_info['public_key_type']} {cert_info['public_key_bits']} bits")

    # Protocolos soportados
    protocols = analysis.get('protocols', {})
    print("\nPROTOCOLOS SOPORTADOS:")
    for protocol, supported in protocols.items():
        status = "✓ Habilitado" if supported else "✗ Deshabilitado"
        print(f"{protocol}: {status}")

    # Cifrados soportados
    ciphers = analysis.get('ciphers', [])
    if ciphers:
        print("\nCIFRADOS SOPORTADOS:")
        current_protocol = ""
        for cipher in ciphers[:10]:  # Mostrar solo los primeros 10 cifrados
            protocol = cipher.get('protocol', 'Unknown')
            if protocol != current_protocol:
                print(f"\n{protocol}:")
                current_protocol = protocol
            print(f"  - {cipher.get('name', 'Unknown')}")

        if len(ciphers) > 10:
            print(f"\n... y {len(ciphers) - 10} cifrados más")

    # Problemas de seguridad
    issues = analysis.get('security_issues', [])
    if issues:
        print("\nPROBLEMAS DE SEGURIDAD DETECTADOS:")
        for i, issue in enumerate(issues, 1):
            severity = issue.get('severity', 'DESCONOCIDO')
            issue_name = issue.get('issue', 'Problema desconocido')
            description = issue.get('description', 'Sin descripción')
            print(f"  {i}. [{severity}] {issue_name}")
            print(f"     {description}")
    else:
        print("\nNo se detectaron problemas de seguridad específicos.")

    # Conclusión
    print("\nCONCLUSIÓN:")
    conclusion_message = ""

    high_severity_issues = [i for i in issues if i.get('severity') == 'ALTO']
    medium_severity_issues = [
        i for i in issues if i.get('severity') == 'MEDIO']

    if not issues:
        message = "La configuración SSL/TLS parece ser segura. No se detectaron problemas específicos."
        print(f"[+] {message}")
        conclusion_message = message
    elif high_severity_issues:
        message = f"Se encontraron {len(high_severity_issues)} problemas de seguridad de alta severidad que requieren atención inmediata."
        print(f"[!] {message}")
        conclusion_message = message
    elif medium_severity_issues:
        message = f"Se encontraron {len(medium_severity_issues)} problemas de seguridad de severidad media que deberían ser revisados."
        print(f"[!] {message}")
        conclusion_message = message
    else:
        message = f"Se encontraron {len(issues)} problemas de seguridad de baja severidad."
        print(f"[!] {message}")
        conclusion_message = message

    # Anunciar conclusión con voz
    speak_text(conclusion_message, voice_enabled)


# Función principal para ejecutar el análisis desde línea de comandos
if __name__ == "__main__":
    if len(sys.argv) > 2:
        target_ip = sys.argv[1]
        port = int(sys.argv[2])
        analysis = analyze_ssl_configuration(target_ip, port)
        display_ssl_analysis(analysis, target_ip, port)
    else:
        print("Uso: python ssl_analyzer.py <dirección_ip> <puerto>")
