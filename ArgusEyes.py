#!/usr/bin/env python3

from utils.voice_utils import speak_text
from analyzers.vulnerability_correlation import analyze_attack_vectors
from scanners.osint_module import run_osint_analysis as run_osint_scan
from scanners.fuzzing_module import run_fuzzing_scan
from scanners.iot_scanner import run_iot_scan
from port_scanner import scan_ip, display_results, export_results
from datetime import datetime
import argparse
import os
import sys
import time
import colorama
from colorama import Fore, Back, Style
import shutil


# Importar módulos del proyecto


def mostrar_banner():
    """
    Muestra un banner ASCII atractivo para el programa, centrado dinámicamente.
    """
    colorama.init(autoreset=True)
    banner_lines = [
        f"{Fore.RED}       .         .(,. @@%#( ,,...(....   ...*.(., .,.((&@& .,(.         .   ....",
        f"{Fore.RED}       .          ,,//,% #@%##%%(,..*/.*(#(/,*/*%&##&@@ %*//,,          . ..   .",
        f"{Fore.RED}  .                   ,,.,&,@@%&&#( .,...,,///#&(#@@*#,.,,   .        .   . ....",
        f"{Fore.RED}                %  ,,,,*@,. ,  .%(/,*,...,,*(#%# .., ..@#,,,,..(        ...   ..",
        f"{Fore.RED}           ,  /,,,(%%@@@*%    /.@%,/,#..,,#/#*#@ *    %%@@@%&(,,,.    .    .....",
        f"{Fore.RED}        ,,&(#%&%@@%@&%@%##%    .#&@(%,*.,(,#,@@&.    %%#%&@%#&@@%,%#%%,,... ....",
        f"{Fore.RED}           ,  /    .,(%(.%*.     *#&@%....(@&#%     ./%,#%&,,       ,.  .. .....",
        f"{Fore.RED}            , .#, *,,%%#%#,&.. .  .,#&@@@@&%/.     *#,/%%%%,,% ,   ,  .. ......",
        f"{Fore.RED}             ,  . . .,&%%//%(/%#    (@.@@/@#    (%/(%(/%%@,,.   .., ....  ......",
        f"{Fore.RED}               , .( ,*&(.@@%&@#(/#  .&%@@#@*  //(#@@%&@.#@,*.,. ,     .... .....",
        f"{Fore.RED}                 ,   ,#(%/ @ &//@%%. #&&%@%  &#@&#% &./#((,  .,          ......."
    ]

    try:
        terminal_width = shutil.get_terminal_size().columns
    except OSError:
        terminal_width = 80  # Valor por defecto si no se puede obtener el tamaño

    for line in banner_lines:
        print(line.center(terminal_width))

    print(f"{Fore.RED}{'=' * terminal_width}")
    print(f"{Fore.CYAN}Cre4te by Alzh31m3r".center(terminal_width))
    print(f"{Fore.RED}{'=' * terminal_width}\n")


def mostrar_menu():
    """
    Muestra un menú interactivo con las opciones disponibles
    """
    print(f"{Fore.RED}[*] Seleccione una opción:")
    print(f"{Fore.WHITE}[1] {Fore.YELLOW}Escaneo de puertos estándar")
    print(f"{Fore.WHITE}[2] {Fore.YELLOW}Escaneo rápido")
    print(f"{Fore.WHITE}[3] {Fore.YELLOW}Escaneo completo")
    print(f"{Fore.WHITE}[4] {Fore.YELLOW}Análisis de dispositivos IoT")
    print(f"{Fore.WHITE}[5] {Fore.YELLOW}Fuzzing de aplicaciones web")
    print(f"{Fore.WHITE}[6] {Fore.YELLOW}Recolección de información OSINT")
    print(f"{Fore.WHITE}[7] {Fore.YELLOW}Análisis de vulnerabilidades")
    print(f"{Fore.WHITE}[0] {Fore.RED}Salir")
    print(f"\n{Fore.CYAN}[*] Opciones adicionales:")
    print(f"{Fore.WHITE}[v] {Fore.GREEN}Activar/Desactivar asistente de voz")
    print(f"{Fore.WHITE}[o] {Fore.GREEN}Especificar archivo de salida")
    print(f"{Fore.GREEN}{'=' * 70}\n")


def obtener_target():
    """
    Solicita al usuario la dirección IP o dominio a escanear
    """
    while True:
        target = input(
            f"{Fore.CYAN}[?] Ingrese la dirección IP o dominio a escanear: {Fore.WHITE}")
        if target.strip():
            return target
        print(
            f"{Fore.RED}[!] Debe ingresar una dirección IP o dominio válido.")


def main():
    """
    Función principal que maneja la interfaz interactiva
    """
    colorama.init(autoreset=True)
    voice_enabled = False
    output_file = None
    target = None

    # Verificar si se pasaron argumentos por línea de comandos
    if len(sys.argv) > 1:
        # Configurar el parser de argumentos
        parser = argparse.ArgumentParser(
            description='Escáner de Puertos y Vulnerabilidades con Asistente de Voz',
            formatter_class=argparse.RawTextHelpFormatter
        )

        # Argumentos generales
        parser.add_argument('target', nargs='?',
                            help='Dirección IP o dominio a escanear')
        parser.add_argument('-t', '--type', choices=['default', 'rapido', 'completo', 'iot', 'web', 'osint'],
                            default='default', help='Tipo de escaneo a realizar')
        parser.add_argument('-v', '--voice', action='store_true',
                            help='Habilitar asistente de voz')
        parser.add_argument(
            '-o', '--output', help='Guardar resultados en archivo')

        # Argumentos específicos para cada tipo de escaneo
        parser.add_argument('--iot', action='store_true',
                            help='Realizar escaneo específico de dispositivos IoT')
        parser.add_argument('--fuzzing', action='store_true',
                            help='Realizar fuzzing de directorios y archivos web')
        parser.add_argument('--osint', action='store_true',
                            help='Realizar recolección de información OSINT')

        args = parser.parse_args()

        # Ejecutar con los argumentos proporcionados
        target = args.target
        voice_enabled = args.voice
        output_file = args.output

        # Ejecutar el tipo de escaneo seleccionado
        if args.iot:
            results = run_iot_scan(args.target, args.type, args.voice)
        elif args.fuzzing:
            results = run_fuzzing_scan(args.target, args.voice)
        elif args.osint:
            results = run_osint_scan(args.target, args.voice)
        else:
            # Escaneo estándar de puertos
            results = scan_ip(args.target, args.type, args.voice)
            if results:
                display_results(results, args.voice)

        # Exportar resultados si se especificó un archivo de salida
        if args.output and results:
            export_results(results, args.output)
            print(f"\n[*] Resultados guardados en {args.output}")
            speak_text(f"Resultados guardados en archivo", args.voice)

        print(f"\n{Fore.GREEN}===== ESCANEO COMPLETADO =====\n")
        speak_text("Escaneo completado", args.voice)
        return

    # Modo interactivo con menú
    mostrar_banner()

    while True:
        if not target:
            target = obtener_target()

        mostrar_menu()
        opcion = input(
            f"{Fore.CYAN}[?] Ingrese su opción: {Fore.WHITE}").lower()

        if opcion == '0':
            print(f"\n{Fore.YELLOW}[*] Saliendo del programa...")
            break

        elif opcion == 'v':
            voice_enabled = not voice_enabled
            estado = "activado" if voice_enabled else "desactivado"
            print(f"\n{Fore.GREEN}[*] Asistente de voz {estado}")
            if voice_enabled:
                speak_text(f"Asistente de voz {estado}", True)
            continue

        elif opcion == 'o':
            output_file = input(
                f"{Fore.CYAN}[?] Ingrese la ruta del archivo de salida: {Fore.WHITE}")
            print(
                f"\n{Fore.GREEN}[*] Archivo de salida establecido: {output_file}")
            continue

        # Ejecutar la opción seleccionada
        results = None
        scan_type = 'default'

        if opcion == '1':
            scan_type = 'default'
            results = scan_ip(target, scan_type, voice_enabled)
        elif opcion == '2':
            scan_type = 'rapido'
            results = scan_ip(target, scan_type, voice_enabled)
        elif opcion == '3':
            scan_type = 'completo'
            results = scan_ip(target, scan_type, voice_enabled)
        elif opcion == '4':
            results = run_iot_scan(target, 'default', voice_enabled)
        elif opcion == '5':
            results = run_fuzzing_scan(target, voice_enabled)
        elif opcion == '6':
            results = run_osint_scan(target, voice_enabled)
        elif opcion == '7':
            if os.path.exists('vulnerabilities.json'):
                analyze_attack_vectors('vulnerabilities.json', voice_enabled)
            else:
                print(f"{Fore.RED}[!] No se encontró el archivo 'vulnerabilities.json'. Realice un escaneo primero.")
            continue
        else:
            print(f"{Fore.RED}[!] Opción no válida. Intente de nuevo.")
            continue

        if results:
            display_results(results, voice_enabled)
            if output_file:
                export_results(results, output_file)
                print(f"\n[*] Resultados guardados en {output_file}")
                speak_text(f"Resultados guardados en archivo", voice_enabled)

        print(f"\n{Fore.GREEN}===== ESCANEO COMPLETADO =====\n")
        speak_text("Escaneo completado", voice_enabled)

        # Preguntar si desea realizar otro escaneo
        otro_escaneo = input(f"{Fore.CYAN}[?] ¿Desea realizar otro escaneo? (s/n): {Fore.WHITE}").lower()
        if otro_escaneo != 's':
            break
        else:
            target = None
            output_file = None

if __name__ == "__main__":
    main()
