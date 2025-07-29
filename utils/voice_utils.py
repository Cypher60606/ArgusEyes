#!/usr/bin/env python3

import pyttsx3


def speak_text(text, voice_enabled=True):
    """
    Convierte texto a voz utilizando pyttsx3

    Args:
        text (str): Texto a convertir en voz
        voice_enabled (bool): Indica si la voz está habilitada
    """
    if not voice_enabled:
        return

    try:
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()
    except Exception as e:
        print(f"\n[!] Error al utilizar el asistente de voz: {e}")
