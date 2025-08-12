ComboToolPro GUI - Herramienta de procesamiento de combos
Pitón Licencia

ComboToolPro GUI es una aplicación diseñada para procesar y manipular listas de combos (usuario:contraseña) con múltiples funciones útiles para pentesters y profesionales de seguridad.

Características principales
Eliminación de duplicados
Extracción por dominios
Filtrado por patrones específicos
Estadísticas de dominios
Organización de líneas
División y combinación de archivos
Interfaz gráfica moderna y fácil de usar.
Requisitos
Python 3.8 o superior
Windows 10/11 (recomendado)
Instalación y uso
1. Clonar el repositorio
git clone https://github.com/DarkPierc/Combo-Tools.git
cd Combo-Tools
1.1 Cambiar a la rama ULP
En la rama ULP se encuentra la última versión estable del proyecto que incluye las opciones extraer registros y buscar en registros. Estas opciones están disponibles en la pestaña de herramientas de la interfaz gráfica.

git checkout ulp
1.2 Actualizar la rama principal con los cambios remotos
git pull origin main
2. Crear y activar entorno virtual (Windows)
python -m venv venv
venv\Scripts\activate
3. Instalar dependencias
pip install -r requirements.txt
4. Ejecutar la aplicación
python main.py
Generación de archivo ejecutable (.exe)
Para crear un archivo ejecutable independiente:

Asegúrese de tener PyInstaller instalado (viene en requisitos.txt)
Ejecuta el script de creación:
python crear_exe.py main.py
El ejecutable se generará en la carpeta dist/con el nombre ComboToolProGUI.exe.

Opciones adicionales para crear_exe.py
Icono personalizado : Coloca un archivo .icocon el mismo nombre que tu script o icono.icoen el mismo directorio
Ocultar consola : El guión ya incluye la opción --noconsolepor defecto.
Un solo archivo : Se genera un único archivo .exepara facilitar la distribución
Estructura del proyecto
Combo-Tools/
│
├── dist/                    # Carpeta con ejecutables generados
├── venv/                    # Entorno virtual (no incluido en repo)
│
├── main.py                  # Script principal de la aplicación
├── crear_exe.py             # Script para generar .exe
├── requirements.txt         # Dependencias del proyecto
├── README.md                # Este archivo
└── icono.ico                # Icono opcional para el ejecutable
Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un problema o solicitud de extracción para sugerencias o mejoras.

Soporte
Para problemas o preguntas, abra un problema en el repositorio o contacte al desarrollador.
