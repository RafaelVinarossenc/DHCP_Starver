


from datetime import datetime
import random
import netifaces
import ipaddress
import scapy.all as scapy
import utils

#### CLASSES #### ------------------------------------------------------
class fake_host:
    """
    Defines basic parameters of a host
    """
    def __init__(self, mac_address, transaction_id, ip_address=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.transaction_id = transaction_id
        #self.hostname = "elvispresley"
        self.hostname = utils.get_random_hostname()
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
        instance = cls(mac_address=data["mac_address"], transaction_id=data["transaction_id"], ip_address=data["ip_address"])
        #instance.ip_address = data["ip_address"]
        instance.hostname = data["hostname"]
        instance.lease_time = data["lease_time"]
        instance.acquisition_time = datetime.strptime(data["acquisition_time"], "%Y-%m-%d %H:%M:%S")
        instance.is_spoofed = data["is_spoofed"]
        instance.is_server = data["is_server"]
        return instance
    
    @classmethod
    def create_host(cls, ip_address=None):
        trans_id = random.getrandbits(32)
        mac_address = utils.get_random_mac()
        return cls(mac_address, trans_id, ip_address)



#### COMMON FUNCTIONS #### --------------------------------------------------------
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


def get_hosts_from_network(ip_address, netmask):
    """
    Returns a list of all possible assignable IP addresses to hosts on the interface network
    """
    network = ipaddress.IPv4Network(ip_address + "/" + netmask, strict=False)
    # List of avalaible addresses
    address_list = [str(ip_address) for ip_address in network.hosts()] 
    return address_list


def mac_to_str(bytes_value):
    """
    Converts bytes sequence to standard hex MAC address format (ff:ff:ff:ff:ff:ff)
    """
    hex_string = ''.join('{:02x}'.format(byte) for byte in bytes_value)
    formatted_mac_address = ':'.join(hex_string[i:i+2] for i in range(0, 12, 2))
    return formatted_mac_address


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