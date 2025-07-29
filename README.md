🔭 ArgusEye
👁️ Reconocimiento Cibernético con Visión Total y Asistente de Voz
ArgusEye es una herramienta avanzada de reconocimiento digital, capaz de escanear puertos, recopilar OSINT, detectar dispositivos IoT, mapear vulnerabilidades, y ahora también interactuar por comandos de voz.

📦 Requisitos del sistema
Antes de instalar ArgusEye, asegúrate de tener lo siguiente:
- Python 3.8 o superior
- Git instalado
- Acceso a internet
- Sistema operativo compatible: Linux, macOS o Windows
- Terminal o consola con permisos administrativos (solo si necesitas escanear redes externas)

🧰 Instalación paso a paso
# 1️⃣ Clona el repositorio
git clone https://github.com/Cypher60606/ArgusEyes.git

# 2️⃣ Entra al directorio
cd arguseye

# 3️⃣ Crea un entorno virtual (opcional pero recomendado)
python -m venv venv
source venv/bin/activate   # En Linux/macOS
venv\Scripts\activate      # En Windows

# 4️⃣ Instala las dependencias
pip install -r requirements.txt

# 5️⃣ (Opcional) Configura claves API si quieres funcionalidades OSINT extendidas
# Edita el archivo .env o config.py con tus claves de Shodan, Censys, etc.



🔧 Cómo usar
# Ejecuta el script principal
python arguseye.py


Una vez iniciado, podrás elegir entre las siguientes opciones interactivas:
- Escaneo de puertos locales o remotos
- Análisis OSINT sobre dominios o IPs
- Detección de dispositivos IoT en red
- Activación del asistente de voz para ejecutar comandos por voz

🗣️ Activación del Asistente de Voz
Para usar el asistente de voz integrado:
- Verifica que tu sistema tenga entrada de micrófono habilitada.
- Ejecuta el comando:
python arguseye.py --voice


- Da tus comandos en voz alta, por ejemplo:
- “Escanear puerto 80 en 192.168.1.1”
“Buscar información OSINT sobre dominio ejemplo.com”


📂 Estructura del proyecto
arguseye/
│
├── arguseye.py             # Script principal
├── modules/                # Funciones separadas por categoría
│   ├── port_scanner.py
│   ├── osint_tools.py
│   ├── iot_detector.py
│   ├── voice_assistant.py
│   └── vuln_mapper.py
├── assets/                 # Imágenes, logos o íconos
├── requirements.txt        # Dependencias
└── README.md               # Este archivo



⚠️ Aviso Legal
ArgusEye debe usarse exclusivamente para fines educativos o auditorías debidamente autorizadas. El autor no se hace responsable del mal uso de esta herramienta.
