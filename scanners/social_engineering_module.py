#!/usr/bin/env python3

from utils.voice_utils import speak_text
import os
import sys
import json
import random
from datetime import datetime

# Importar utilidades
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Plantillas base para campañas de phishing
PHISHING_TEMPLATES = {
    "correo_corporativo": {
        "asunto": "Actualización urgente de credenciales corporativas",
        "cuerpo": "Estimado/a {nombre}:\n\nNuestro departamento de TI ha detectado actividad inusual en su cuenta corporativa. Por motivos de seguridad, es necesario que actualice sus credenciales inmediatamente.\n\nPor favor, haga clic en el siguiente enlace para verificar su identidad y actualizar sus credenciales: {enlace_malicioso}\n\nEste enlace expirará en 24 horas.\n\nAtentamente,\nDepartamento de Seguridad Informática\n{empresa}",
        "firma": "Este es un mensaje automático, por favor no responda a este correo."
    },
    "servicio_financiero": {
        "asunto": "Alerta de seguridad: Verificación de cuenta bancaria requerida",
        "cuerpo": "Estimado/a cliente {nombre}:\n\nHemos detectado un intento de acceso no autorizado a su cuenta bancaria. Para proteger sus fondos, hemos bloqueado temporalmente su cuenta.\n\nPara desbloquear su cuenta, verifique su identidad en el siguiente enlace: {enlace_malicioso}\n\nSi no completa este proceso en las próximas 48 horas, su cuenta permanecerá bloqueada por motivos de seguridad.\n\nGracias por su comprensión,\n",
        "firma": "Departamento de Seguridad\n{empresa}\nEste mensaje es confidencial y está destinado únicamente al destinatario mencionado."
    },
    "paqueteria": {
        "asunto": "Notificación de entrega pendiente - Acción requerida",
        "cuerpo": "Hola {nombre},\n\nTenemos un paquete pendiente de entrega a su nombre. Intentamos entregarlo el {fecha}, pero no pudimos completar la entrega.\n\nPara programar una nueva entrega, por favor confirme sus datos en: {enlace_malicioso}\n\nSi no recibimos su confirmación en 3 días, el paquete será devuelto al remitente.\n\n",
        "firma": "Servicio de Atención al Cliente\n{empresa}\nPor favor no responda a este correo, es un envío automático."
    },
    "premio": {
        "asunto": "¡Felicidades! Ha sido seleccionado para un premio especial",
        "cuerpo": "Estimado/a {nombre},\n\n¡Felicidades! Su dirección de correo electrónico ha sido seleccionada en nuestro sorteo mensual.\n\nHa ganado un {premio} valorado en {valor}.\n\nPara reclamar su premio, complete el formulario de verificación en: {enlace_malicioso}\n\nTiene 7 días para reclamar su premio antes de que sea reasignado a otro participante.\n\n",
        "firma": "Departamento de Promociones\n{empresa}"
    },
    "actualizacion_software": {
        "asunto": "Actualización crítica de seguridad disponible",
        "cuerpo": "Estimado/a usuario/a {nombre},\n\nHemos lanzado una actualización crítica de seguridad para {software} que corrige vulnerabilidades graves que podrían comprometer su sistema.\n\nPor favor, descargue e instale la actualización inmediatamente desde: {enlace_malicioso}\n\nIgnorar esta actualización podría dejar su sistema vulnerable a ataques.\n\n",
        "firma": "Equipo de Seguridad\n{empresa}"
    }
}

# Información para personalizar las plantillas


def generate_phishing_template(target_info, template_type="correo_corporativo"):
    """
    Genera una plantilla de phishing personalizada basada en la información del objetivo

    Args:
        target_info (dict): Información del objetivo para personalizar la plantilla
        template_type (str): Tipo de plantilla a utilizar

    Returns:
        dict: Plantilla de phishing personalizada
    """
    try:
        # Verificar si el tipo de plantilla existe
        if template_type not in PHISHING_TEMPLATES:
            print(
                f"[!] Tipo de plantilla '{template_type}' no válido. Usando plantilla corporativa por defecto.")
            template_type = "correo_corporativo"

        # Obtener la plantilla base
        template = PHISHING_TEMPLATES[template_type].copy()

        # Personalizar la plantilla con la información del objetivo
        nombre = target_info.get("nombre", "Usuario")
        empresa = target_info.get("empresa", "Empresa S.A.")
        enlace_malicioso = target_info.get(
            "enlace_malicioso", "https://sitio-malicioso.com/login")
        fecha = target_info.get("fecha", datetime.now().strftime("%d/%m/%Y"))
        premio = target_info.get("premio", "smartphone de última generación")
        valor = target_info.get("valor", "$1,000")
        software = target_info.get("software", "su aplicación")

        # Reemplazar variables en la plantilla
        template["cuerpo"] = template["cuerpo"].format(
            nombre=nombre,
            empresa=empresa,
            enlace_malicioso=enlace_malicioso,
            fecha=fecha,
            premio=premio,
            valor=valor,
            software=software
        )

        # Reemplazar variables en la firma si existe
        if "firma" in template:
            template["firma"] = template["firma"].format(
                empresa=empresa
            )

        return template

    except Exception as e:
        print(f"[!] Error al generar plantilla de phishing: {e}")
        return None


def create_phishing_campaign(target_info, campaign_type="correo_corporativo", voice_enabled=False):
    """
    Crea una campaña de phishing personalizada

    Args:
        target_info (dict): Información del objetivo
        campaign_type (str): Tipo de campaña de phishing
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Información de la campaña de phishing
    """
    try:
        print(
            f"\n[*] Creando campaña de phishing de tipo '{campaign_type}'...")
        speak_text(f"Creando campaña de phishing personalizada", voice_enabled)

        # Generar plantilla de phishing
        template = generate_phishing_template(target_info, campaign_type)
        if not template:
            return None

        # Crear estructura de la campaña
        campaign = {
            "tipo": campaign_type,
            "fecha_creacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "objetivo": target_info,
            "plantilla": template,
            "asunto": template["asunto"],
            "cuerpo": template["cuerpo"],
            "firma": template.get("firma", "")
        }

        # Guardar la campaña en un archivo
        output_dir = "resultados_phishing"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/phishing_{campaign_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(campaign, f, indent=4, ensure_ascii=False)

        print(f"[+] Campaña de phishing creada y guardada en {filename}")
        speak_text("Campaña de phishing creada exitosamente", voice_enabled)

        return campaign

    except Exception as e:
        print(f"[!] Error al crear campaña de phishing: {e}")
        return None


def run_social_engineering_campaign(target, campaign_type="correo_corporativo", voice_enabled=False):
    """
    Ejecuta una campaña de ingeniería social

    Args:
        target (str): Objetivo de la campaña (dominio o dirección de correo)
        campaign_type (str): Tipo de campaña a ejecutar
        voice_enabled (bool): Indica si el asistente de voz está habilitado

    Returns:
        dict: Resultados de la campaña
    """
    try:
        print(f"\n===== INICIANDO CAMPAÑA DE INGENIERÍA SOCIAL =====\n")
        speak_text("Iniciando campaña de ingeniería social", voice_enabled)

        # Extraer información básica del objetivo
        domain = target.split("@")[-1] if "@" in target else target
        company_name = domain.split(".")[0].capitalize()

        # Información simulada del objetivo (en un caso real se obtendría de OSINT)
        target_info = {
            "nombre": "Usuario",
            "empresa": company_name,
            "dominio": domain,
            "enlace_malicioso": f"https://fake-{domain}.malicious-site.com/login",
            "fecha": datetime.now().strftime("%d/%m/%Y"),
            "premio": "smartphone de última generación",
            "valor": "$1,000",
            "software": "su aplicación de seguridad"
        }

        # Crear campaña de phishing
        campaign = create_phishing_campaign(
            target_info, campaign_type, voice_enabled)
        if not campaign:
            return None

        # Mostrar detalles de la campaña
        print("\n[+] Detalles de la campaña de phishing:")
        print(f"Tipo: {campaign['tipo']}")
        print(f"Asunto: {campaign['asunto']}")
        print("\nCuerpo del mensaje:")
        print("-" * 50)
        print(campaign['cuerpo'])
        print(campaign['firma'])
        print("-" * 50)

        # Resultados de la campaña
        results = {
            "campaign_type": campaign_type,
            "target": target,
            "template": campaign['tipo'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": campaign
        }

        print("\n[*] Campaña de ingeniería social completada")
        speak_text("Campaña de ingeniería social completada", voice_enabled)

        return results

    except Exception as e:
        print(f"[!] Error al ejecutar campaña de ingeniería social: {e}")
        return None


# Función principal para pruebas
if __name__ == "__main__":
    target = "usuario@empresa.com"
    run_social_engineering_campaign(target, "correo_corporativo", False)