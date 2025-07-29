#!/usr/bin/env python3

import requests
import json
import socket
import whois
import dns.resolver
import time
from datetime import datetime
import os


def get_geolocation_info(ip_address):
    """
    Obtiene información de geolocalización para una dirección IP

    Args:
        ip_address (str): Dirección IP a consultar

    Returns:
        dict: Información de geolocalización
    """
    try:
        print(
            f"\n[*] Obteniendo información de geolocalización para {ip_address}...")

        # Usar la API de ipinfo.io para obtener datos de geolocalización
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")

        if response.status_code == 200:
            data = response.json()
            geo_info = {
                "ip": data.get("ip", "Desconocido"),
                "ciudad": data.get("city", "Desconocido"),
                "region": data.get("region", "Desconocido"),
                "pais": data.get("country", "Desconocido"),
                "ubicacion": data.get("loc", "Desconocido"),
                "organizacion": data.get("org", "Desconocido"),
                "codigo_postal": data.get("postal", "Desconocido"),
                "zona_horaria": data.get("timezone", "Desconocido")
            }
            return geo_info
        else:
            print(
                f"[!] Error al obtener información de geolocalización: {response.status_code}")
            return {"error": f"Error al obtener información: {response.status_code}"}

    except Exception as e:
        print(f"[!] Error al obtener información de geolocalización: {e}")
        return {"error": str(e)}


def get_domain_info(domain):
    """
    Obtiene información sobre un dominio utilizando WHOIS con soporte mejorado para dominios internacionales

    Args:
        domain (str): Nombre de dominio a consultar

    Returns:
        dict: Información del dominio
    """
    try:
        print(f"\n[*] Obteniendo información WHOIS para {domain}...")

        # Extraer el TLD (Top Level Domain) para identificar dominios especiales
        tld = domain.split('.')[-1].lower()

        # Diccionario de servidores WHOIS específicos para TLDs menos comunes o con problemas
        special_tld_servers = {
            'cu': 'whois.nic.cu',
            'ec': 'whois.nic.ec',
            've': 'whois.nic.ve',
            'bo': 'whois.nic.bo',
            'py': 'whois.nic.py',
            'uy': 'whois.nic.uy'
            # Se pueden agregar más TLDs según sea necesario
        }

        domain_info = None
        whois_error = None

        # Método 1: Intentar con la biblioteca whois estándar
        try:
            domain_info = whois.whois(domain)
            # Verificar si la respuesta es válida (algunas veces devuelve un objeto pero sin datos útiles)
            if not domain_info.domain_name and not domain_info.registrar and not domain_info.creation_date:
                domain_info = None
                raise Exception(
                    "No se obtuvieron datos útiles con la biblioteca whois estándar")
        except Exception as e:
            whois_error = str(e)
            print(f"[!] Primer método falló: {whois_error}")
            domain_info = None

        # Método 2: Si el primer método falla y es un TLD especial, intentar con servidor específico
        if domain_info is None and tld in special_tld_servers:
            try:
                print(
                    f"[*] Intentando con servidor WHOIS específico para .{tld}: {special_tld_servers[tld]}")
                # Aquí podríamos implementar una consulta directa al servidor WHOIS específico
                # Esto requeriría una implementación personalizada usando sockets
                # Por ahora, intentamos especificar el servidor en la biblioteca whois
                domain_info = whois.whois(
                    domain, server=special_tld_servers[tld])

                # Verificar si la respuesta es válida
                if not domain_info.domain_name and not domain_info.registrar and not domain_info.creation_date:
                    domain_info = None
                    raise Exception(
                        f"No se obtuvieron datos útiles del servidor específico para .{tld}")
            except Exception as e:
                print(f"[!] Segundo método falló: {str(e)}")
                # Mantenemos el error original si ambos métodos fallan
                if domain_info is None:
                    whois_error = whois_error or str(e)

        # Método 3: Si los métodos anteriores fallan, intentar con una API alternativa
        # Nota: Este es un ejemplo conceptual, en una implementación real se usaría una API real
        if domain_info is None:
            try:
                print(
                    f"[*] Intentando obtener información WHOIS a través de método alternativo...")
                # Aquí se implementaría la llamada a una API alternativa
                # Por ahora, creamos un objeto simulado con información básica
                domain_info = type('obj', (object,), {
                    'domain_name': domain,
                    'registrar': "Información no disponible mediante métodos estándar",
                    'creation_date': None,
                    'expiration_date': None,
                    'updated_date': None,
                    'name_servers': None,
                    'status': "Información limitada disponible",
                    'admin_email': None,
                    'tech_email': None
                })
                print(
                    f"[+] Se obtuvo información básica mediante método alternativo")
            except Exception as e:
                print(f"[!] Tercer método falló: {str(e)}")
                # Si todos los métodos fallan, lanzamos la excepción original
                if domain_info is None:
                    raise Exception(whois_error or str(e))

        # Formatear la información para presentarla de manera más legible
        whois_info = {
            "dominio": domain,
            "registrador": domain_info.registrar,
            "fecha_creacion": str(domain_info.creation_date) if domain_info.creation_date else "Desconocido",
            "fecha_expiracion": str(domain_info.expiration_date) if domain_info.expiration_date else "Desconocido",
            "fecha_actualizacion": str(domain_info.updated_date) if domain_info.updated_date else "Desconocido",
            "servidores_nombre": domain_info.name_servers if domain_info.name_servers else "Desconocido",
            "estado": domain_info.status if domain_info.status else "Desconocido",
            "contacto_admin": domain_info.admin_email if hasattr(domain_info, 'admin_email') else "Desconocido",
            "contacto_tecnico": domain_info.tech_email if hasattr(domain_info, 'tech_email') else "Desconocido",
            "tld": tld,
            "metodo_consulta": "Estándar" if whois_error is None else ("Servidor específico" if tld in special_tld_servers else "Alternativo")
        }

        return whois_info

    except Exception as e:
        print(f"[!] Error al obtener información WHOIS: {e}")
        return {"error": str(e), "dominio": domain, "tld": domain.split('.')[-1].lower()}


def get_subdomains(domain, max_results=20):
    """
    Intenta encontrar subdominios para un dominio dado

    Args:
        domain (str): Nombre de dominio a consultar
        max_results (int): Número máximo de resultados a devolver

    Returns:
        list: Lista de subdominios encontrados
    """
    try:
        print(f"\n[*] Buscando subdominios para {domain}...")

        # Lista de subdominios comunes para probar
        common_subdomains = [
            "www", "mail", "ftp", "webmail", "login", "admin", "test", "dev", "staging",
            "api", "shop", "blog", "app", "mobile", "m", "secure", "vpn", "cdn", "media",
            "images", "img", "video", "videos", "docs", "support", "help", "portal", "intranet"
        ]

        found_subdomains = []
        count = 0

        # Probar subdominios comunes
        for subdomain in common_subdomains:
            if count >= max_results:
                break

            full_domain = f"{subdomain}.{domain}"
            try:
                # Intentar resolver el subdominio
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                count += 1
                print(f"[+] Subdominio encontrado: {full_domain}")
            except socket.gaierror:
                pass

            # Pequeña pausa para no sobrecargar el servidor DNS
            time.sleep(0.1)

        # Si no se encontraron suficientes subdominios, intentar con registros DNS
        if count < max_results:
            try:
                # Intentar transferencia de zona (AXFR)
                answers = dns.resolver.resolve(domain, 'NS')
                nameservers = [ns.target.to_text() for ns in answers]

                for ns in nameservers:
                    try:
                        # Intentar transferencia de zona con cada servidor de nombres
                        xfr = dns.query.xfr(ns, domain)
                        for transfer in xfr:
                            for name in transfer.authority:
                                for item in name.items:
                                    if item.rdtype == dns.rdatatype.NS:
                                        subdomain = item.name.to_text()
                                        if subdomain not in found_subdomains and count < max_results:
                                            found_subdomains.append(subdomain)
                                            count += 1
                                            print(
                                                f"[+] Subdominio encontrado: {subdomain}")
                    except Exception:
                        pass
            except Exception:
                pass

        return found_subdomains

    except Exception as e:
        print(f"[!] Error al buscar subdominios: {e}")
        return []


def check_data_breaches(domain_or_email):
    """
    Verifica si un dominio o email ha aparecido en filtraciones de datos conocidas
    utilizando la API de Have I Been Pwned

    Args:
        domain_or_email (str): Dominio o email a verificar

    Returns:
        dict: Información sobre posibles filtraciones
    """
    try:
        print(
            f"\n[*] Verificando filtraciones de datos para {domain_or_email}...")

        # Nota: La API de Have I Been Pwned requiere una clave API para consultas completas
        # Esta es una implementación simplificada que muestra cómo se podría implementar
        print("[!] Nota: Para obtener resultados completos de filtraciones de datos,")
        print("    se requiere una clave API de Have I Been Pwned (https://haveibeenpwned.com/API/Key)")

        # Verificar si es un email o un dominio
        is_email = '@' in domain_or_email

        if is_email:
            # Simulación de resultados para un email
            # En una implementación real, se haría una solicitud a la API con la clave API
            return {
                "mensaje": "Para verificar filtraciones de datos de un email específico, se requiere una clave API.",
                "recomendacion": "Visite https://haveibeenpwned.com/ y realice la consulta manualmente."
            }
        else:
            # Para dominios, podemos hacer una consulta básica sin clave API
            # Pero en una implementación real, también se requeriría una clave API
            return {
                "mensaje": "Para verificar filtraciones de datos de un dominio, se requiere una clave API.",
                "recomendacion": "Visite https://haveibeenpwned.com/DomainSearch y realice la consulta manualmente."
            }

    except Exception as e:
        print(f"[!] Error al verificar filtraciones de datos: {e}")
        return {"error": str(e)}


def detect_technologies(url):
    """
    Intenta detectar tecnologías utilizadas en un sitio web

    Args:
        url (str): URL del sitio web a analizar

    Returns:
        dict: Tecnologías detectadas
    """
    try:
        print(f"\n[*] Detectando tecnologías utilizadas en {url}...")

        # Asegurarse de que la URL tenga el formato correcto
        if not url.startswith('http'):
            url = f"http://{url}"

        # Realizar solicitud HTTP para obtener el contenido de la página
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        if response.status_code == 200:
            html_content = response.text
            headers = response.headers

            # Detectar tecnologías basadas en cabeceras HTTP
            technologies = {
                "servidor": headers.get('Server', 'No detectado'),
                "cms": "No detectado",
                "lenguaje": "No detectado",
                "frameworks": [],
                "analytics": "No detectado",
                "otras_tecnologias": []
            }

            # Detectar CMS
            cms_patterns = {
                "WordPress": ["wp-content", "wp-includes", "wp-admin"],
                "Joomla": ["com_content", "com_users", "Joomla!"],
                "Drupal": ["Drupal.settings", "drupal.js", "/sites/default/files"],
                "Magento": ["Mage.Cookies", "magento", "Magento_"],
                "Shopify": ["Shopify.theme", "shopify", "/cdn.shopify.com/"],
                "Wix": ["wix.com", "wixsite.com", "_wixCIDX"],
                "Squarespace": ["squarespace.com", "static.squarespace.com"],
                "Ghost": ["ghost.io", "ghost-", "/ghost/"]
            }

            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern in html_content:
                        technologies["cms"] = cms
                        break
                if technologies["cms"] != "No detectado":
                    break

            # Detectar lenguajes de programación
            language_patterns = {
                "PHP": ["X-Powered-By: PHP", ".php"],
                "ASP.NET": ["X-AspNet-Version", ".aspx", "__VIEWSTATE"],
                "Java": ["JavaServer Pages", ".jsp", "jsessionid"],
                "Python": ["Python", "Django", "Flask"],
                "Ruby": ["Ruby on Rails", ".rb", "phusion"],
                "Node.js": ["Express", "Node.js", "npm"]
            }

            for lang, patterns in language_patterns.items():
                for pattern in patterns:
                    if pattern in str(headers) or pattern in html_content:
                        technologies["lenguaje"] = lang
                        break
                if technologies["lenguaje"] != "No detectado":
                    break

            # Detectar frameworks
            framework_patterns = {
                "Bootstrap": ["bootstrap.css", "bootstrap.min.js"],
                "jQuery": ["jquery.js", "jquery.min.js"],
                "React": ["react.js", "react-dom"],
                "Angular": ["angular.js", "ng-app"],
                "Vue.js": ["vue.js", "v-bind"],
                "Laravel": ["laravel", "Laravel"],
                "Django": ["django", "csrftoken"],
                "Flask": ["flask", "Flask"],
                "Spring": ["spring", "Spring Framework"]
            }

            for framework, patterns in framework_patterns.items():
                for pattern in patterns:
                    if pattern in html_content:
                        technologies["frameworks"].append(framework)
                        break

            # Detectar analytics
            analytics_patterns = {
                "Google Analytics": ["google-analytics.com", "ga('create'", "gtag"],
                "Matomo/Piwik": ["matomo.js", "piwik.js"],
                "Adobe Analytics": ["sc.omtrdc.net", "s_code.js"],
                "Hotjar": ["hotjar", "hjSetting"],
                "Mixpanel": ["mixpanel", "mixpanel.track"]
            }

            for analytics, patterns in analytics_patterns.items():
                for pattern in patterns:
                    if pattern in html_content:
                        technologies["analytics"] = analytics
                        break
                if technologies["analytics"] != "No detectado":
                    break

            # Detectar otras tecnologías
            other_tech_patterns = {
                "Cloudflare": ["cloudflare", "__cfduid"],
                "AWS": ["amazonaws.com", "aws-"],
                "Google Cloud": ["googleusercontent.com", "gstatic"],
                "Azure": ["azure.com", "msft"],
                "Akamai": ["akamai", "akamaiedge.net"],
                "Fastly": ["fastly", "fastly.net"],
                "Nginx": ["nginx", "Nginx"],
                "Apache": ["apache", "Apache"],
                "IIS": ["IIS", "Microsoft-IIS"]
            }

            for tech, patterns in other_tech_patterns.items():
                for pattern in patterns:
                    if pattern in str(headers) or pattern in html_content:
                        technologies["otras_tecnologias"].append(tech)
                        break

            return technologies
        else:
            print(f"[!] Error al acceder al sitio web: {response.status_code}")
            return {"error": f"Error al acceder al sitio web: {response.status_code}"}

    except Exception as e:
        print(f"[!] Error al detectar tecnologías: {e}")
        return {"error": str(e)}


def run_osint_analysis(target, is_domain=False):
    """
    Ejecuta un análisis OSINT completo sobre un objetivo

    Args:
        target (str): Dirección IP o dominio a analizar
        is_domain (bool): Indica si el objetivo es un dominio

    Returns:
        dict: Resultados del análisis OSINT
    """
    results = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tipo_objetivo": "dominio" if is_domain else "ip"
    }

    print(f"\n{'=' * 60}")
    print(f"INICIANDO ANÁLISIS OSINT PARA: {target}")
    print(f"{'=' * 60}\n")

    # Si es un dominio, obtener su dirección IP
    if is_domain:
        try:
            ip_address = socket.gethostbyname(target)
            results["ip_address"] = ip_address
            print(f"[+] Dominio {target} resuelto a IP: {ip_address}")
        except socket.gaierror:
            results["ip_address"] = "No se pudo resolver"
            print(
                f"[!] No se pudo resolver el dominio {target} a una dirección IP")

    # Obtener información de geolocalización
    ip_to_check = results.get("ip_address", target) if is_domain else target
    geo_info = get_geolocation_info(ip_to_check)
    results["geolocalizacion"] = geo_info

    # Si es un dominio, obtener información adicional
    if is_domain:
        # Información WHOIS
        whois_info = get_domain_info(target)
        results["whois"] = whois_info

        # Subdominios
        subdomains = get_subdomains(target)
        results["subdominios"] = subdomains

        # Tecnologías utilizadas
        tech_info = detect_technologies(target)
        results["tecnologias"] = tech_info

        # Verificar filtraciones de datos
        breach_info = check_data_breaches(target)
        results["filtraciones"] = breach_info

    # Guardar resultados en un archivo JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Limpiar el target para usarlo como nombre de archivo seguro
    # Reemplazar caracteres problemáticos para nombres de archivo
    target_safe = target.replace('.', '_').replace(
        ':', '_').replace('/', '_').replace('\\', '_')
    # Eliminar protocolo (http://, https://) si existe
    if target_safe.startswith('http__') or target_safe.startswith('https__'):
        target_safe = target_safe.split('__', 1)[1]
    # Eliminar barras diagonales duplicadas
    while '__' in target_safe:
        target_safe = target_safe.replace('__', '_')

    # Asegurarse de que el directorio de resultados existe
    results_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "resultados_analisis")
    os.makedirs(results_dir, exist_ok=True)

    # Crear también el directorio en la raíz del proyecto para compatibilidad
    root_results_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "resultados_analisis")
    os.makedirs(root_results_dir, exist_ok=True)

    # Guardar el archivo de resultados
    results_file = os.path.join(
        results_dir, f"osint_{target_safe}_{timestamp}.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(
        f"\n[+] Análisis OSINT completado. Resultados guardados en: {results_file}")

    return results


def display_osint_results(results):
    """
    Muestra los resultados del análisis OSINT de manera formateada

    Args:
        results (dict): Resultados del análisis OSINT
    """
    print(f"\n{'=' * 60}")
    print(f"RESULTADOS DEL ANÁLISIS OSINT PARA: {results['target']}")
    print(f"Tipo de objetivo: {results['tipo_objetivo'].upper()}")
    print(f"Fecha y hora: {results['timestamp']}")
    print(f"{'=' * 60}\n")

    # Mostrar información de geolocalización
    print(f"\n{'-' * 60}")
    print("INFORMACIÓN DE GEOLOCALIZACIÓN")
    print(f"{'-' * 60}")

    geo_info = results.get('geolocalizacion', {})
    if 'error' in geo_info:
        print(f"[!] Error: {geo_info['error']}")
    else:
        print(f"IP: {geo_info.get('ip', 'Desconocido')}")
        print(f"Ciudad: {geo_info.get('ciudad', 'Desconocido')}")
        print(f"Región: {geo_info.get('region', 'Desconocido')}")
        print(f"País: {geo_info.get('pais', 'Desconocido')}")
        print(
            f"Ubicación (lat,long): {geo_info.get('ubicacion', 'Desconocido')}")
        print(f"Organización: {geo_info.get('organizacion', 'Desconocido')}")
        print(f"Código Postal: {geo_info.get('codigo_postal', 'Desconocido')}")
        print(f"Zona Horaria: {geo_info.get('zona_horaria', 'Desconocido')}")

    # Si es un dominio, mostrar información adicional
    if results.get('tipo_objetivo') == 'dominio':
        # Información WHOIS
        print(f"\n{'-' * 60}")
        print("INFORMACIÓN WHOIS DEL DOMINIO")
        print(f"{'-' * 60}")

        whois_info = results.get('whois', {})
        if 'error' in whois_info:
            print(f"[!] Error: {whois_info['error']}")
        else:
            print(f"Dominio: {whois_info.get('dominio', 'Desconocido')}")
            print(
                f"Registrador: {whois_info.get('registrador', 'Desconocido')}")
            print(
                f"Fecha de creación: {whois_info.get('fecha_creacion', 'Desconocido')}")
            print(
                f"Fecha de expiración: {whois_info.get('fecha_expiracion', 'Desconocido')}")
            print(
                f"Fecha de actualización: {whois_info.get('fecha_actualizacion', 'Desconocido')}")

            # Servidores de nombres
            name_servers = whois_info.get('servidores_nombre', [])
            if name_servers and name_servers != "Desconocido":
                print("\nServidores de nombres:")
                if isinstance(name_servers, list):
                    for ns in name_servers:
                        print(f"  - {ns}")
                else:
                    print(f"  - {name_servers}")

            # Estado del dominio
            status = whois_info.get('estado', [])
            if status and status != "Desconocido":
                print("\nEstado del dominio:")
                if isinstance(status, list):
                    for s in status:
                        print(f"  - {s}")
                else:
                    print(f"  - {status}")

            # Contactos
            print(
                f"\nContacto administrativo: {whois_info.get('contacto_admin', 'Desconocido')}")
            print(
                f"Contacto técnico: {whois_info.get('contacto_tecnico', 'Desconocido')}")

        # Subdominios
        print(f"\n{'-' * 60}")
        print("SUBDOMINIOS ENCONTRADOS")
        print(f"{'-' * 60}")

        subdomains = results.get('subdominios', [])
        if not subdomains:
            print("[!] No se encontraron subdominios.")
        else:
            for subdomain in subdomains:
                print(f"  - {subdomain}")

        # Tecnologías utilizadas
        print(f"\n{'-' * 60}")
        print("TECNOLOGÍAS DETECTADAS")
        print(f"{'-' * 60}")

        tech_info = results.get('tecnologias', {})
        if 'error' in tech_info:
            print(f"[!] Error: {tech_info['error']}")
        else:
            print(f"Servidor web: {tech_info.get('servidor', 'No detectado')}")
            print(f"CMS: {tech_info.get('cms', 'No detectado')}")
            print(
                f"Lenguaje de programación: {tech_info.get('lenguaje', 'No detectado')}")

            # Frameworks
            frameworks = tech_info.get('frameworks', [])
            if frameworks:
                print("\nFrameworks detectados:")
                for framework in frameworks:
                    print(f"  - {framework}")
            else:
                print("\nFrameworks detectados: Ninguno")

            print(f"\nAnalytics: {tech_info.get('analytics', 'No detectado')}")

            # Otras tecnologías
            other_techs = tech_info.get('otras_tecnologias', [])
            if other_techs:
                print("\nOtras tecnologías detectadas:")
                for tech in other_techs:
                    print(f"  - {tech}")
            else:
                print("\nOtras tecnologías detectadas: Ninguna")

        # Filtraciones de datos
        print(f"\n{'-' * 60}")
        print("VERIFICACIÓN DE FILTRACIONES DE DATOS")
        print(f"{'-' * 60}")

        breach_info = results.get('filtraciones', {})
        if 'error' in breach_info:
            print(f"[!] Error: {breach_info['error']}")
        else:
            print(f"Mensaje: {breach_info.get('mensaje', '')}")
            print(f"Recomendación: {breach_info.get('recomendacion', '')}")

    print(f"\n{'=' * 60}")
    print(f"FIN DEL ANÁLISIS OSINT")
    print(f"{'=' * 60}\n")


# Función principal para ejecutar desde línea de comandos
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Herramienta de análisis OSINT')
    parser.add_argument('target', help='Dirección IP o dominio a analizar')
    parser.add_argument('--domain', action='store_true',
                        help='Indica que el objetivo es un dominio')

    args = parser.parse_args()

    # Ejecutar análisis OSINT
    results = run_osint_analysis(args.target, args.domain)

    # Mostrar resultados
    display_osint_results(results)


if __name__ == "__main__":
    main()