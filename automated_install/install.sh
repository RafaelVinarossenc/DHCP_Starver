#!/bin/bash

# Download and extraction
wget https://github.com/RafaelVinarossenc/DHCP_Starver/archive/refs/heads/master.zip
unzip master.zip && rm master.zip
#rm master.zip
mv DHCP_Starver-master/ dhcp_starver

# Install Python3 if needed
echo "Checking if Python3 is installed"
if command -v python3 &>/dev/null; then
    echo "Python 3 is already installed."
else
    echo "Python 3 not installed. Installing now."
    sudo apt-get update
    sudo apt-get install -y python3
    if command -v python3 &>/dev/null; then
        echo "Python 3 successfully installed."
    else
        echo "Problem during Python3 install. Install it manually and try again."
        exit 1
    fi
fi

# Create python virtual environment
echo "Setting permissions to dhcp_starver/ and creating Python virtual environment"
mkdir -p dhcp_starver/python_env

# Setting permissions
chmod -R u+wx,g+wx,o+wx dhcp_starver/

python3 -m venv dhcp_starver/python_env 
if [ $? -eq 0 ]; then
    echo "Virtual environment successfully created in dhcp_starver/python_env."
else
    echo "Problem occurred during virtual environment setup."
    exit 1
fi

# Installing libraries
# Activar el entorno virtual
source dhcp_starver/python_env/bin/activate
# Instalar las librerías en el entorno virtual
pip install nmap netifaces scapy
if [ $? -eq 0 ]; then
    echo "Libraries successfully installed in the virtual environment."
else
    echo "Problem occurred during libraries installation in the virtual environment."
    deactivate
    exit 1
fi

# Deactivate the virtual environment
deactivate