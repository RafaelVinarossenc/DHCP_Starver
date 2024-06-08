#!/bin/bash

# Nombre del paquete (tal como se especificó en setup.py)
PACKAGE_NAME="nombre-de-tu-paquete"

# Directorio del repositorio (cambiar si es necesario)
REPO_DIR="tu-repositorio-main"

# Función para desinstalar el paquete
uninstall_package() {
    echo "Desinstalando el paquete $PACKAGE_NAME..."
    pip uninstall -y $PACKAGE_NAME
}

# Función para eliminar el directorio del repositorio
remove_repo_dir() {
    if [ -d "$REPO_DIR" ]; then
        echo "Eliminando el directorio del repositorio..."
        rm -rf "$REPO_DIR"
    else
        echo "El directorio del repositorio no existe o ya ha sido eliminado."
    fi
}

# Ejecutar las funciones
uninstall_package
remove_repo_dir

echo "Desinstalación completa."