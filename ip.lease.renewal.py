# ip.lease.renewal.py


#### IMPORTS #### -------------------------------------------------------------------
import threading
from pathlib import Path
from common import *
from utils import setup_logging, write_to_log, file_semaphore


#### CONFIG #### -------------------------------------------------------------------
timeout_to_receive_dhcp_response = 10 # seconds

base_dir = Path(__file__).resolve().parent
log_file = base_dir / "logs" / "lease_renewal.log"

setup_logging(log_file)


#### FUNCTIONS #### ----------------------------------------------------------------

def is_ip_renew_needed(lease_time, acquisition_time):
    """
    Compares adquisition time and time now to evaluate if an IP renewal is needed
    """
    # Sometimes lease time/acquisition_time are not correctly assigned to host. idk
    try:
        # Substracting 30 seconds to threshold to compensate delay between first and last IP address renewal
        threshold = 0.5 * lease_time - 30
        time_diff = datetime.now() - acquisition_time
    except TypeError:
        # Forcing IP renew
        return True
    
    if threshold < time_diff.total_seconds():
        return True
    else:
        return False


def send_renewal_request(host, dhcp_server_ip, dhcp_server_mac):
    """
    Send Unicast DHCP Request for IP address lease renewal
    """

    
    dhcp_request_packet = create_unicast_dhcp_request_packet(host, dhcp_server_ip, dhcp_server_mac)
    # Send Unicast DHCP Request packet requesting an IP address lease renewal to DHCP server
    scapy.sendp(dhcp_request_packet, verbose=False, iface=iface)

    write_to_log(f"DHCP Request sent: {host.mac_address} renewing {host.ip_address}")

    # Waits until timeout or DHCP Response is received
    dhcp_request_response = process_dhcp_packet(dhcp_request_packet[scapy.BOOTP].xid, timeout_to_receive_dhcp_response)

    # If there's response
    if dhcp_request_response:
        
        print(f"{dhcp_request_response.summary()}")
        # Check what kind of DHCP response is
        response_type = handle_dhcp_response(dhcp_request_response, host)

        if response_type == "ACK":
            # DORA handshake completed, saving new host to json file
            write_to_log(f"ACK received: {host.mac_address} successfully renewed to {host.ip_address}")
            host_dict = {}
            host_dict[host.ip_address] = host
            update_json_file(host_dict, json_file, file_semaphore)
            # IP acquisition successfull
            return True
        
        elif response_type == "NAK":
            
            # If NAK is received, renew failed and that IP address is no longer spoofed
            write_to_log(f"DHCP NAK received: {host.mac_address} failed to renew {host.ip_address}")
            # Remove that host from JSON file or put it's is_spoofed flag to False
            try:
                hosts_dict = load_from_json(hosts_file, file_semaphore)
            except Exception as e:
                write_to_log(f"Error loading JSON file: {str(e)}")
                pass
            # Remove that IP from dictionary
            hosts_dict.pop(host.ip_address)
            # Save modified dictionary to JSON file
            try:
                save_to_json(hosts_dict, hosts_file, file_semaphore)
            except Exception as e:
                write_to_log(f"{str(e)}")

        else:
            write_to_log(f"Unknown DHCP response received: DHCP.MessageType = {dhcp_request_packet[scapy.DHCP].options[0][1]}")
            return


def create_unicast_dhcp_request_packet(host, dst_ip, dst_mac):
    """
    Create a Unicast DHCP Request packet
    """
    # Converting MAC address from string typical format to a 16 bytes sequence, needed for BOOTP/DHCP header 
    mac_address = int(host.mac_address.replace(":", ""), 16).to_bytes(6, "big")
    # Making DHCP Request packet
    ether_header = scapy.Ether(src=mac_address, 
                               dst=dst_mac)
    ip_header = scapy.IP(src=host.ip_address, 
                         dst=dst_ip)
    udp_header = scapy.UDP(sport=68, 
                           dport=67)
    bootp_field = scapy.BOOTP(chaddr=mac_address, 
                              ciaddr=host.ip_address,
                              xid=host.transaction_id,
                              flags=0)
    dhcp_field = scapy.DHCP(options=[("message-type", "request"),
                                     ("client_id", b'\x01' + mac_address),
                                     ("server_id", dst_ip),
                                     ('param_req_list', [53, 54, 51, 1, 6, 3, 50]),
                                     ("requested_addr", host.ip_address), 
                                     ("hostname", host.hostname),
                                     "end"])
    dhcp_request = (ether_header/ip_header/udp_header/bootp_field/dhcp_field)
    return dhcp_request


def find_dhcp_server():
    """
    Check and find DHCP server on known router JSON file
    """
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

    for server_data in dhcp_server_dict.values():

        return server_data.ip_address, server_data.mac_address
    
    return None, None


def main():
    
    write_to_log(f"Starting DHCP IP lease renewal service")
    
    # Load previous results from JSON file
    try:
        host_dict = load_from_json(json_file, file_semaphore)
    except FileNotFoundError as e:
        write_to_log(str(e))
        host_dict = {}
    except json.JSONDecodeError as e:
        write_to_log(f"Error decoding JSON file: {str(e)}")
        host_dict = {}
    except Exception as e:
        write_to_log(f"An unexpected error occurred: {str(e)}")
        host_dict = {}
    
    dhcp_server_ip, dhcp_server_mac = find_dhcp_server()

    # Start response DHCP packet capture thread
    capture_thread = threading.Thread(target=capture_dhcp_packets, args=(captured_packets, iface))
    capture_thread.daemon = True
    capture_thread.start()

    # For every host on dict decides if a new DHCP Request is needed to keep IP address linked to host
    for host in host_dict.values():
        if is_ip_renew_needed(host.lease_time, host.acquisition_time) and host.is_spoofed:
            # Resetting Transaction ID
            host.transaction_id = random.getrandbits(32)
            # Unicast DHCP Request to renew IP address lease
            send_renewal_request(host, dhcp_server_ip, dhcp_server_mac)

    write_to_log(f"Service Terminated")
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        write_to_log(f"Service manually terminated")


