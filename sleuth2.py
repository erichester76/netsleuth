import scapy.all as scapy
import pynetbox
import socket
import logging
from pyp0f.fingerprint import fingerprint_tcp
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP, TCP

# NetBox API settings
NETBOX_API_URL = "http://<netbox_url>/"
NETBOX_API_TOKEN = "<your_netbox_api_token>"

# Initialize pynetbox API client
nb = pynetbox.api(NETBOX_API_URL, token=NETBOX_API_TOKEN)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# Get local IP for directionality checks
local_ip = scapy.get_if_addr(scapy.conf.iface)

vendor_data = {}
with open('oui.txt', 'r') as file:
    for line in file:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) == 2:
            mac_prefix = parts[0].upper()
            vendor = parts[1].upper()
            vendor_data[mac_prefix] = vendor
        else:
            mac_prefix = parts[0].upper()
            vendor = parts[2].upper()
            vendor_data[mac_prefix] = vendor

def add_device_to_netbox(device_data):
    """Send inventory data to NetBox."""
    try:
        log.debug(f"Attempting to add/update device: {device_data}")
        existing_device = nb.dcim.devices.get(name=device_data['name'])
        if existing_device:
            log.info(f"[NetBox] Updating existing device: {device_data['name']}")
            existing_device.update(
                {
                    "device_role": nb.dcim.device_roles.get(name=device_data['device_role']).id,
                    "device_type": nb.dcim.device_types.get(model="Generic Device").id,
                    "site": nb.dcim.sites.get(name="Default Site").id,
                    "primary_ip4": nb.ipam.ip_addresses.get(address=device_data['primary_ip']).id if device_data['primary_ip'] != "Unknown" else existing_device.primary_ip4,
                    "mac_address": device_data['mac_address'],
                    "manufacturer": nb.dcim.manufacturers.get(name=device_data['manufacturer']).id,
                    "platform": nb.dcim.platforms.get(name=device_data['platform']).id if device_data.get('platform') else existing_device.platform,
                }
            )
            log.debug(f"[NetBox] Device updated: {device_data['name']}")
        else:
            nb.dcim.devices.create(
                name=device_data['name'],
                device_role=nb.dcim.device_roles.get(name=device_data['device_role']).id,
                device_type=nb.dcim.device_types.get(model="Generic Device").id,
                site=nb.dcim.sites.get(name="Default Site").id,
                primary_ip4=nb.ipam.ip_addresses.create(address=device_data['primary_ip']).id,
                mac_address=device_data['mac_address'],
                manufacturer=nb.dcim.manufacturers.get(name=device_data['manufacturer']).id,
                platform=nb.dcim.platforms.get(name=device_data['platform']).id if device_data.get('platform') else None
            )
            log.info(f"[NetBox] Device added: {device_data['name']}")
    except Exception as e:
        log.error(f"[NetBox] Failed to add/update device: {e}")

def get_hostname(ip):
    """Attempt to resolve the hostname via reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        log.debug(f"Resolved hostname for IP {ip}: {hostname}")
        return hostname
    except socket.herror:
        log.debug(f"Hostname resolution failed for IP {ip}")
        return "Unknown"

def build_device_record(packet):
    """Construct a device record from packet information considering directionality."""
    log.debug("Building device record from packet...")
    device_data = {
        "name": "Unknown",
        "mac_address": "Unknown",
        "manufacturer": "Unknown",
        "primary_ip": "Unknown",
        "device_role": "Unknown",
        "platform": None,
    }

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        mac_prefix_src = src_mac[:8].upper()
        mac_prefix_dst = dst_mac[:8].upper()

        # Determine directionality
        if src_mac != scapy.get_if_hwaddr(scapy.conf.iface):  # Inbound traffic
            device_data["mac_address"] = src_mac
            device_data["manufacturer"] = vendor_data.get(mac_prefix_src, "Unknown")
            log.debug(f"Inbound traffic detected. Source MAC: {src_mac}, Vendor: {device_data['manufacturer']}")
        elif dst_mac != scapy.get_if_hwaddr(scapy.conf.iface):  # Outbound traffic
            return None
            device_data["mac_address"] = dst_mac
            device_data["manufacturer"] = vendor_data.get(mac_prefix_dst, "Unknown")
            log.debug(f"Outbound traffic detected. Destination MAC: {dst_mac}, Vendor: {device_data['manufacturer']}")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Determine directionality
        if src_ip != local_ip:  # Inbound traffic
            device_data["primary_ip"] = src_ip
            device_data["name"] = get_hostname(src_ip)
            log.debug(f"Inbound traffic detected. Source IP: {src_ip}, Hostname: {device_data['name']}")
        elif dst_ip != local_ip:  # Outbound traffic
            device_data["primary_ip"] = dst_ip
            log.debug(f"Outbound traffic detected. Destination IP: {dst_ip}")

    if packet.haslayer(DHCP):
        for option in packet[DHCP].options:
            if isinstance(option, tuple):
                key, value = option
                if key == 'hostname':
                    device_data["name"] = value
                    log.debug(f"DHCP hostname option found: {value}")
                elif key == 'router':
                    device_data["device_role"] = "Router"
                    log.debug(f"DHCP router option found: {value}")

    if packet.haslayer(DNS) and packet[UDP].sport == 5353:
        for i in range(packet[DNS].ancount):
            answer = packet[DNS].an[i]
            if hasattr(answer, "rrname"):
                device_data["name"] = answer.rrname.decode().split('.')[0]
                log.debug(f"mDNS query response found: {device_data['name']}")

    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN packet
        tcp_result = fingerprint_tcp(packet)
        if tcp_result.match:
            device_data["platform"] = tcp_result.match.record.label.name
            log.debug(f"OS fingerprint detected: {device_data['platform']}")

    log.debug(f"Device record built: {device_data}")
    return device_data

def process_packet(packet):
    try:
        log.debug("Processing packet...")
        device_data = build_device_record(packet)
        if device_data.get("name") != "Unknown":
            add_device_to_netbox(device_data)
        else:
            log.info("Packet processed, but no actionable device data found.")
    except Exception as e:
        log.error(f"Error processing packet: {e}")

def monitor_interfaces():
    log.info("Starting packet capture...")
    try:
        scapy.sniff(prn=process_packet, store=False)
    except Exception as e:
        log.error(f"Error during packet capture: {e}")

if __name__ == "__main__":
    monitor_interfaces()
