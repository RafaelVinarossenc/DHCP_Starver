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

# Function to check if Linux package is installed
is_installed() {
    local tool=$1
    if [[ "$tool" == "net-tools" ]]; then
        command -v ifconfig &>/dev/null
    else
        ! apt-cache policy $tool | grep -q "Installed: (none)"
    fi
}

# Function to add unique crontab entries avoiding duplicates
add_crontab_entry() {
    local entry="$1"
    local current_crontab=$(crontab -l 2>/dev/null)
    if ! echo "$current_crontab" | grep -Fq "$entry"; then
        (crontab -l 2>/dev/null; echo "$entry") | crontab -
    fi
}


# Variables -------------------------------------------------------
GITHUB_REPO_URL="https://github.com/RafaelVinarossenc/DHCP_Starver/archive/refs/heads/master.zip"
LINUX_PACKAGES=("python3" "python3-dev" "net-tools" "iptables" "unzip")


# Main Script -----------------------------------------------------
# Check if script is running as root ------------------------------
if [ "$EUID" -ne 0 ]; then
    print_color "$RED" "Please run as root"
    exit 1
fi


# Install required packeges if needed --------------------------------------
for tool in "${LINUX_PACKAGES[@]}"; do
    print_color "$YELLOW" "Checking if $tool is installed..."

    if is_installed $tool; then
        print_color "$GREEN" "$tool is already installed."
    else
        print_color "$RED" "$tool not installed, installing it now..."
        sudo apt-get update
        sudo apt-get install -y $tool

        # Check if installation was successfull
        if is_installed $tool; then
            print_color "$GREEN" "$tool successfully installed."
        else
            print_color "$RED" "Problem during $tool installation."
            read -rp "If this is an error, you can continue normally. Continue with script execution? [y/N]: " continue_installation
            if [[ ! $continue_installation =~ ^[Yy]$ ]]; then
                remove_and_terminate
            fi
        fi
    fi
done


# Download and extraction -----------------------------------------
print_color "$YELLOW" "Downloading tool from GitHub repository to dhcp_starver/"
wget $GITHUB_REPO_URL -O master.zip
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


# Create python virtual environment ---------------------------------------------
print_color "$YELLOW" "Setting permissions to $DHCP_STARVER_DIR/ and creating Python virtual environment."
mkdir -p $DHCP_STARVER_DIR/python_venv
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


# Device interfaces configuration ---------------------------------------------------
print_color "$YELLOW" "Available network interfaces:"
interfaces=($(ls /sys/class/net))

for i in "${!interfaces[@]}"; do
    echo "$((i + 1)). ${interfaces[$i]}"
done

read -rp "Select the network interface to use [1, 2, ...]: " interface_index
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

# Pi-Hole configuration
# Prompt to reset administrator password
print_color "$YELLOW" "Changing pi-Hole administrator password used to access Web interface..."
pihole -a -p

# Setting up Pi-Hole's DHCP Server
#pihole -a enabledhcp "RANGE START IP" "RANGE END IP" "GATEWAY IP" "LEASE TIME(hours)" "DOMAIN"
print_color "$YELLOW" "Enabling DHCP Server..."
pihole -a enabledhcp "192.168.255.10" "192.168.255.200" "192.168.255.1" "24" "pi-local"

# Config completed
IP_ADDRESS=$(hostname -I | awk '{print $1}')
print_color $GREEN "Configuration completed. Access Pi-hole administration interface at http://$IP_ADDRESS/admin"


# Creating startup configuration file -----------------------------------------------
print_color "$YELLOW" "Creating startup configuration file on $DHCP_STARVER_DIR/startup_config.sh"
startup_script="$DHCP_STARVER_DIR/startup_config.sh"
bash -c "cat > $startup_script" <<EOL
#!/bin/bash

export PATH=$PATH:/usr/local/bin:/usr/bin:/bin

echo "startup_script.sh executed at $(date)" >> /home/pi/dhcp_starver/startup.log

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

# Make sure Pi-Hole's DHCP Server is set-up correctly
pihole -a enabledhcp "192.168.255.10" "192.168.255.200" "192.168.255.1" "24" "pi-local"
EOL

chmod +x $startup_script

print_color $GREEN "Contents of $startup_script:"
cat "$startup_script"

echo " "
# Adding Crontab entries ------------------------------------------------------------
print_color "$YELLOW" "Adding Crontab entries..."

add_crontab_entry "# Run DHCP Starver startup configuration on reboot"
add_crontab_entry "@reboot sleep 30 && $startup_script"

add_crontab_entry "# Execute pool.exhaustion.py on reboot with 60 seconds of delay and once every hour"
add_crontab_entry "@reboot sleep 60 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/pool.exhaustion.py"
add_crontab_entry "0 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/pool.exhaustion.py"

add_crontab_entry "# Execute dhcp.spoof.py on reboot with 180 seconds of delay and once every 10 minutes"
add_crontab_entry "@reboot sleep 180 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/dhcp.spoof.py"
add_crontab_entry "*/10 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/dhcp.spoof.py"

add_crontab_entry "# Execute ip.lease.renewal.py on reboot with 180 seconds of delay and once every minute"
add_crontab_entry "@reboot sleep 270 && $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/ip.lease.renewal.py"
add_crontab_entry "*/1 * * * * $DHCP_STARVER_DIR/python_venv/bin/python $DHCP_STARVER_DIR/ip.lease.renewal.py"

print_color $GREEN "Crontab entries added. Displaying current existing entries:"
crontab -l

echo " "
print_color $BLUE "DHCP Starver tool successfully installed. Please remove install.sh. A system reboot is recommended."
print_color $BLUE "If you want to uninstall the tool, please remove $DHCP_STARVER_DIR and associated entrien in Crontab."