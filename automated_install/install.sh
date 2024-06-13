#!/bin/bash


# Global variables and functions -----------------------------------------------------
# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No color (reset)

print_color() {
    local color="$1"
    local message="$2"
    echo -e "${color}${message}${NC}"
}

remove_and_terminate() {
	echo "Removing dhcp_starver and terminate script"
	rm -r dhcp_starver
    exit 1
}


# Main Script -----------------------------------------------------
# Download and extraction
print_color "$YELLOW" "Downloading tool from GitHub repository to dhcp_starver/"
wget https://github.com/RafaelVinarossenc/DHCP_Starver/archive/refs/heads/master.zip
unzip master.zip && rm master.zip
mv DHCP_Starver-master/ dhcp_starver

# Install Python3 if needed
print_color "$YELLOW" "Checking if Python3 is installed"
if command -v python3 &>/dev/null; then
    print_color "$GREEN" "Python 3 is already installed."
else
    print_color "$YELLOW" "Python 3 not installed, installing it now."
    sudo apt-get update
    sudo apt-get install -y python3
    if command -v python3 &>/dev/null; then
        print_color "$GREEN" "Python 3 successfully installed."
    else
        print_color "$RED" "Problem during Python3 install. Install it manually and try again."
        remove_and_terminate
    fi
fi

# Create python virtual environment
print_color "$YELLOW" "Setting permissions to dhcp_starver/ and creating Python virtual environment."
mkdir -p dhcp_starver/python_env

# Setting permissions
chmod -R u+wx,g+wx,o+wx dhcp_starver/

python3 -m venv dhcp_starver/python_env 
if [ $? -eq 0 ]; then
    print_color "$GREEN" "Virtual environment successfully created in dhcp_starver/python_env."
else
    print_color "$RED" "Problem occurred during virtual environment setup."
    remove_and_terminate
fi

# Installing libraries on virtual environment
print_color "$YELLOW" "Installing libraries on virtual environment"
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