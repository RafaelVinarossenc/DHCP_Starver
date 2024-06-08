#!/bin/bash

# URL del archivo zip
URL="https://github.com/RafaelVinarossenc/DHCP_Starver.zip"
ZIP_FILE="dhcp_starver.zip"
DIR_NAME="dhcp_starver"

# Descargar el archivo zip
echo "Descargando el repositorio..."
curl -L -o $ZIP_FILE $URL

# Extraer el archivo zip
echo "Extrayendo los archivos..."
unzip $ZIP_FILE

# Cambiar al directorio del repositorio
cd $DIR_NAME

# Instalar las dependencias
echo "Instalando dependencias..."
pip install -r requirements.txt

# Instalar el paquete
echo "Instalando el paquete..."
pip install .

echo "Instalación completa."