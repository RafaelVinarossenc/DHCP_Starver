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
	echo "Removing $DHCP_STARVER_DIR and terminate script"
	rm -r $DHCP_STARVER_DIR
    exit 1
}


# Main Script -----------------------------------------------------
# Check if script is running as root ------------------------------
if [ "$EUID" -ne 0 ]; then
    print_color "$RED" "Please run as root"
    exit 1
fi


# Download and extraction -----------------------------------------
print_color "$YELLOW" "Downloading tool from GitHub repository to dhcp_starver/"
wget https://github.com/RafaelVinarossenc/DHCP_Starver/archive/refs/heads/master.zip
unzip master.zip && rm master.zip
mv DHCP_Starver-master/ dhcp_starver

# Get absolute path of dhcp_starver directory
DHCP_STARVER_DIR=$(realpath dhcp_starver)

# Creating additional folders for logs
print_color "$YELLOW" "Creating folder $DHCP_STARVER_DIR/logs..."
mkdir $DHCP_STARVER_DIR/logs

# Checking if JSON files exists
FILES=("bogus_hosts.json" "known_router.json" "known_hosts.json")

for file in "${FILES[@]}"; do
    FILE_PATH="$DHCP_STARVER_DIR/$file"
    print_color "$YELLOW" "Checking $file..."
    # Check if exists
    if [ -f "$FILE_PATH" ]; then
        print_color "$GREEN" "$file exists. Clearing content and adding {}."
        echo "{}" > "$FILE_PATH"
    else
        print_color "$RED" "$file does not exist. Creating it and adding {}."
        touch "$FILE_PATH"
        echo "{}" > "$FILE_PATH"
    fi
done


# Install required packeges if needed --------------------------------------
TOOLS=("python3" "python3-dev" "net-tools" "iptables")

for tool in "${TOOLS[@]}"; do
    print_color "$YELLOW" "Checking if $tool is installed..."
    if command -v $tool &>/dev/null; then
        print_color "$GREEN" "$tool is already installed."
    else
        print_color "$RED" "$tool not installed, installing it now..."
        sudo apt-get update
        sudo apt-get install -y $tool
        # Verificar si la instalación fue exitosa
        if command -v $tool &>/dev/null; then
            print_color "$GREEN" "$tool successfully installed."
        else
            print_color "$RED" "Problem during $tool installation. Install it manually and try again."
            remove_and_terminate
        fi
    fi
done


# Create python virtual environment ---------------------------------------------
print_color "$YELLOW" "Setting permissions to $DHCP_STARVER_DIR/ and creating Python virtual environment."
mkdir -p $DHCP_STARVER_DIR/python_env
chmod -R u+wx,g+wx,o+wx $DHCP_STARVER_DIR/
python3 -m venv $DHCP_STARVER_DIR/python_venv 

if [ $? -eq 0 ]; then
    print_color "$GREEN" "Virtual environment successfully created in $DHCP_STARVER_DIR/python_venv."
else
    print_color "$RED" "Problem occurred during virtual environment setup."
    remove_and_terminate
fi

# Installing libraries on virtual environment
print_color "$YELLOW" "Installing libraries on virtual environment"
source $DHCP_STARVER_DIR/python_venv/bin/activate

libraries=("scapy" "netifaces")
for lib in "${libraries[@]}"; do
    print_color "$YELLOW" "Installing $lib..."
    pip install "$lib"
    if [ $? -ne 0 ]; then
        print_color "$RED" "Error installing $lib. Aborting."
        deactivate
        remove_and_terminate
    fi
done

deactivate
print_color "$GREEN" "Libraries successfully installed in the virtual environment."


# Configure device interfaces ---------------------------------------------------
print_color "$YELLOW" "Available network interfaces:"
interfaces=($(ls /sys/class/net))

for i in "${!interfaces[@]}"; do
    echo "$((i + 1)). ${interfaces[$i]}"
done

read -p "Select the network interface to use [1, 2, ...]: " interface_index
selected_interface=${interfaces[$((interface_index - 1))]}

if [[ -z $selected_interface ]]; then
    print_color "$RED" "Invalid selection. Exiting."
    remove_and_terminate
fi

# Enabling promiscuos mode on interface
print_color "$YELLOW" "Setting $selected_interface to promiscuous mode..."
ip link set "$selected_interface" promisc on
if [ $? -eq 0 ]; then
    print_color "$GREEN" "$selected_interface set to promiscuous mode successfully."
else
    print_color "$RED" "Failed to set $selected_interface to promiscuous mode."
    remove_and_terminate
fi

# Configure additional IP 192.168.255.1 for DHCP Server 
print_color "$YELLOW" "Configuring additional IP address on $selected_interface..."
ifconfig "$selected_interface:0" 192.168.255.1/24
if [ $? -eq 0 ]; then
    print_color "$GREEN" "Additional IP address configured successfully on $selected_interface."
else
    print_color "$RED" "Failed to configure additional IP address on $selected_interface."
    remove_and_terminate
fi

# Enable packet forwarding
print_color "$YELLOW" "Enabling IP packet forwarding..."
sysctl -w net.ipv4.ip_forward=1
if [ $? -eq 0 ]; then
    print_color "$GREEN" "IP packet forwarding enabled successfully."
else
    print_color "$RED" "Failed to enable IP packet forwarding."
    remove_and_terminate
fi

# Adding iptables NAT rule
print_color "$YELLOW" "Setting up iptables NAT masquerade rule..."
iptables -t nat -A POSTROUTING -o "$selected_interface" -j MASQUERADE
if [ $? -eq 0 ]; then
    print_color "$GREEN" "iptables NAT masquerade rule set successfully."
else
    print_color "$RED" "Failed to set iptables NAT masquerade rule."
    remove_and_terminate
fi


# Pi-hole installation -------------------------------------------------------
print_color "$YELLOW" "Checking if Pi-hole is installed..."
if command -v pihole &>/dev/null; then
    print_color "$GREEN" "Pi-hole is already installed."
else
    print_color "$RED" "Pi-hole not installed. Installing now..."
    # Installing Pi-Hole in unattended mode
    curl -sSL https://install.pi-hole.net | sudo bash -s -- --unattended
    # Check if installation was successfull
    if command -v pihole &>/dev/null; then
        print_color "$GREEN" "Pi-hole installed successfully."
    else
        print_color "$RED" "Error: Pi-hole installation failed."
        exit 1
    fi
fi

# Configuring Pi-Hole
# Prompt to reset administrator password
print_color "$YELLOW" "Changing pi-Hole administrator password used to access Web interface..."
pihole -a -p

# Setting up Pi-Hole's DHCP Server
#pihole -a enabledhcp "RANGE START IP" "RANGE END IP" "GATEWAY IP" "LEASE TIME(hours)" "DOMAIN"
print_color "$YELLOW" "Enabling DHCP Server..."
pihole -a enabledhcp "192.168.255.10" "192.168.2.200" "192.168.255.1" "24" "pi-local"

# Config completed
IP_ADDRESS=$(hostname -I | awk '{print $1}')
print_color $GREEN "Configuration completed. Access Pi-hole administration interface at:"
print_color $GREEN "http://$IP_ADDRESS/admin"


# Creating startup configuration file -----------------------------------------------
print_color "$YELLOW" "Creating startup configuration file on $DHCP_STARVER_DIR/startup_config.sh"
startup_script="$DHCP_STARVER_DIR/startup_config.sh"
bash -c "cat > $startup_script" <<EOL
#!/bin/bash

INTERFACE="$selected_interface"

# Enable promiscuous mode
ip link set "\$INTERFACE" promisc on

# Add IP address
ifconfig "\$INTERFACE:0" 192.168.255.1/24

# Enable packet forwarding
sysctl -w net.ipv4.ip_forward=1

# iptables rule
iptables -t nat -A POSTROUTING -o "\$INTERFACE" -j MASQUERADE

# Removing Pi-Hole DHCP server's IP lease
rm -f /etc/pihole/dhcp.leases
pihole restartdns
EOL

chmod +x $startup_script


# Adding Crontab entries ------------------------------------------------------------
print_color "$YELLOW" "Adding Crontab entries..."
(crontab -l ; echo "@reboot $network_script") | crontab -
(crontab -l 2>/dev/null; echo "@reboot sleep 60 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/pool.exhaustion.py") | crontab -
(crontab -l 2>/dev/null; echo "0 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/pool.exhaustion.py") | crontab -
(crontab -l 2>/dev/null; echo "@reboot sleep 180 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/dhcp.spoof.py") | crontab -
(crontab -l 2>/dev/null; echo "*/10 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/dhcp.spoof.py") | crontab -
(crontab -l 2>/dev/null; echo "@reboot sleep 270 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/ip.lease.renewal.py") | crontab -
(crontab -l 2>/dev/null; echo "*/1 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/ip.lease.renewal.py") | crontab -
