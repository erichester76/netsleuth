#!/usr/bin/python3

from datetime import datetime
import requests;
import json;
import time
from ipaddress import ip_address
from scapy.all import *
import logging
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.database import DATABASE
from collections import namedtuple
from ndpi import NDPI, NDPIFlow, ffi

#nDPI config
FLOW_KEY = "{} {}:{} <-> {}:{}"
FLOW_STR = "   {} {} [protocol:{}] [category:{}] [confidence:{}] [{} packets/{} bytes]"
PROTOCOL_UNKNWON = 0
flow_cache = {}  # We store the flows in a dictionary.
flow_count = 0  # Flow counter
class Flow(object):
    __slots__ = ("index",
                 "pkts",
                 "bytes",
                 "detected_protocol",
                 "ndpi_flow")

    def __init__(self):
        self.pkts = 0
        self.detected_protocol = None
        self.bytes = 0
        self.ndpi_flow = None



#API Config
BASE_API_URL = "https://lionfish-app-4a33x.ondigitalocean.app/"
API_EMAIL = "eric.hester@umbrella.tech"
API_PASSWORD = "Olsa-Lamp-Fire5"

#LOAD PYP0F DB  
DATABASE.load()

#read in mac vendors file for later lookups
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

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def authenticate():
    url = f"{BASE_API_URL}/auth/login"
    credentials = {
        "email": API_USERNAME,
        "password": API_PASSWORD
    }
    response = requests.post(url, data=json.dumps(credentials))
    response.raise_for_status()  # Raise an exception if the authentication fails
    token = response.json().get('token')  # Get the JWT token from the response
    return token

def find_obj_by_key(endpoint, object_key, object_value):
    # Authenticate and get the JWT token
    token = authenticate()

    # Define the URL of your API
    url = f"{BASE_API_URL}/{endpoint}"

    # Create the headers for your request
    headers = {
        "Authorization": f"Bearer {token}",  # Use the token in the Authorization header
        "Content-Type": "application/json"
    }

    # Send a GET request to the API to check if the object exists
    find_url = f"{url}/find?{object_key}={object_value}"
    response = requests.get(find_url, headers=headers)

    if response.status_code == 200:
        # The object exists, return its ID
        return response.json()
    elif response.status_code == 404:
        # The object does not exist, return None
        return None
    else:
        # An unexpected status code was returned
        response.raise_for_status()

def send_to_api(endpoint, id, data):
    # Authenticate and get the JWT token
    token = authenticate()

    # Define the URL of your API
    url = f"{BASE_API_URL}/{endpoint}"

    # Create the headers for your request
    headers = {
        "Authorization": f"Bearer {token}",  # Use the token in the Authorization header
        "Content-Type": "application/json"
    }

    try:
        if id is not None:
            # The object exists, so update it with a PUT request
            response = requests.put(f"{url}/{id}", data=json.dumps(data), headers=headers)
        else:
            # The object does not exist, so create it with a POST request
            response = requests.post(url, data=json.dumps(data), headers=headers)

    except requests.exceptions.HTTPError as errh:
        print ("HTTP Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print ("Something went wrong with the request:", err)

    else:
        # If the request was successful, print the status code
        print(response.status_code)


#timestamps for dampening alerts later in code
last_alert_timestamps = {}

def alert(ip,event_id,event):

    alert_time = int(time.time())
    key = str(ip) + str(event_id)
    
    #dampen for 1 hour to avoid alert storms
    if key in last_alert_timestamps:
        last_alert_time = last_alert_timestamps[key]
        if alert_time - last_alert_time <= 3600:
            return

    last_alert_timestamps[key] = alert_time 
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    #log.info("[{}] Netsleuth Alert: [{}]: {}".format(timestamp, event_id, event))
    data = {
        "eventId": event_id,
        "event": event 
    }
    save_object('alert',data)

def is_rfc(ip):
    try:
        ip_obj = ip_address(ip)
        if ip == '0.0.0.0': return False
        if ip == '255.255.255.255': return False
        if ip == 0: return False
        return ip_obj.is_private
    except ValueError:
        return False

found = {}

def update_host(direction,type,ip,mac,vlan):

    try:

        hostname = socket.gethostbyaddr(ip)[0]
        hostname = hostname.split(".", 1)[0]

    except socket.herror:
        hostname = "Unknown"

    if mac != '' and mac != 'ff:ff:ff:ff:ff:ff':

        mac_prefix = mac[:8].upper()
        vendor = vendor_data.get(mac_prefix, "Unknown")
        if not mac in found:
            found[mac]=1
            location_id = find_obj_by_key('location','name',LOCATION).get('_id')
            vendor_id = find_obj_by_key('vendor','name',vendor).get('_id')
            vlan_id = find_obj_by_key('vlan','name',vlan).get('_id')
            data = {
                "ipAddress": ip,
                "macAddress": mac,
                "hostName": hostname,
                "location": location_id,
                "vendor": vendor_id,
                "vlan": vlan_id
                "lastSeen": datetime.now
            }
            hardware_id = find_obj_by_key('hardware','macAddress',mac).get('_id')
            send_to_api('hardware', hardware_id, data)
            data = {
                "name": vlan,
            }
            send_to_api('vlan', vlan_id, data)
 
    if direction == 'src' and type == 'arp':
    
        result=sql.fetchone()
        if result is not None: 
            total_arp = result[0]
            total_arp_last_reset = result[1]
            rate = int(total_arp) / int(current_time - total_arp_last_reset + 1)
            if rate > 1 and (current_time - total_arp_last_reset) > 60:
                alert(ip,3001,"[ARP] Possible Scanning Event. ARP requests exceed 1 per second from {}".format(ip))
                total_arp = 0
                total_arp_last_reset = current_time

            total_arp = total_arp + 1
    
    if direction == 'dest' and type == 'arp':
    
        result = sql.fetchone()

        if result is not None: 
            target_count = result[0]
            target_count_last_reset = result[1]

            rate = int(target_count) / int(current_time - target_count_last_reset + 1)
            if rate > 1 and (current_time - target_count_last_reset) > 60:
                alert(ip,3002,"[ARP] Possible POI. ARP requests exceed 1 per second looking for {}".format(ip))
                target_count = 0
                target_count_last_reset = current_time

            target_count = target_count + 1

    
def handle_packet(packet):
    vlan = 0
    srcip = 0
    dstip = 0
    mac = packet[Ether].src

    if packet.haslayer(Dot1Q):
        vlan = packet[Dot1Q].vlan
        vlan_id = find_obj_by_key('vlan','name',vlan).get('_id')
        data = {
           "name": vlan,
        }
        send_to_api('vlan', vlan_id, data)

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if packet[Ether].src != packet[ARP].hwsrc:
            srcip = packet[ARP].psrc
            alert(srcip,3010,"[ARP] Spoofed ARP packet detected for {}".format(srcip))

    if packet.haslayer(ARP) and packet[ARP].op == 1:
        srcip = packet[ARP].psrc
        dstip = packet[ARP].pdst

        if is_rfc(srcip): update_host('src','arp',srcip,mac,vlan)
        if is_rfc(dstip): update_host('dest','arp',dstip,'',vlan)


    elif packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 2:
        
        dhcp_options = packet[DHCP].options
        router = ''
        dhcp_server = ''
        hostname = ''
        dns_server = {}
        subnet_mask = ''
        domain = ''
        for option in dhcp_options:

            if isinstance(option, tuple):
                option_code = option[0]
                option_value = option[1]

                if option_code == 'router':
                    router = option_value
                elif option_code == 'requested-addr':
                    srcip = option_value
                elif option_code == 'server-id':
                    dhcp_server = option_value
                elif option_code == 'hostname':
                    hostname = option_value
                elif option_code == 'dns-server':
                    dns_servers = option_value
                elif option_code == 'subnet_mask':
                    subnet_mask = option_value
                elif option_code == 'domain':
                    domain_name = option_value.decode()

        if srcip and hostname:
            data = {
                "ipAddress": ip,
                "macAddress": mac,
                "hostName": hostname,
                "lastSeen": datetime.now
            }
            hardware_id = find_obj_by_key('hardware','macAddress',mac).get('_id')
            send_to_api('hardware', hardware_id, data)

            alert(srcip,1006,'[DHCP] discovered new hostname '.format(srcip,hostname))

        if router:
            data = {
                "ipAddress": ip,
                "macAddress": mac,
                "hostName": hostname,
                "type": 'router'
                "lastSeen": datetime.now
            }
            hardware_id = find_obj_by_key('hardware','macAddress',mac).get('_id')
            send_to_api('hardware', hardware_id, data)
            data = {
                "name": vlan,
                "ipGateway": router
            }
            vlan_id = find_obj_by_key('vlan','name',vlan).get('_id')
            send_to_api('vlan', vlan_id, data)
 
            alert(srcip,1003,'[DHCP] discovered new router '.format(router))

        if subnet_mask:
            # find network from subnet mask and ip
            data = {
                "name": vlan,
                "ipSubnet": subnet
            }
            vlan_id = find_obj_by_key('vlan','name',vlan).get('_id')
            send_to_api('vlan', vlan_id, data)

    elif packet.haslayer(DNS) and packet.haslayer(UDP):
        if packet[DNS].ancount >=1:
            #if packet.haslayer(IP):
            #    print(packet[IP].src,": ",packet[DNS].an.type," ",packet[DNS].an.rrname.decode())
            # A and AAAA records
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and (packet[DNS].an.type == 1 or packet[DNS].an.type == 28):
                hostname = packet[DNS].an.rrname.decode()
                hostname = hostname.split(".", 1)[0]
                data = {
                    "ipAddress": packet[IP].src,
                    "macAddress": mac,
                    "hostName": hostname,
                    "lastSeen": datetime.now
                }
                hardware_id = find_obj_by_key('hardware','ipAddress',packet[IP].src).get('_id')
                send_to_api('hardware', hardware_id, data)

                alert(srcip,1005,'[MDNS] discovered new hostname '.format(packet[IP].src,hostname))
            #find ipp printers
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and packet[DNS].an.type == 16 and 'ipp' in packet[DNS].an.rrname.decode():
                data = {
                    "ipAddress": packet[IP].src,
                    "macAddress": mac,
                    "type": 'printer',
                    "lastSeen": datetime.now
                }
                hardware_id = find_obj_by_key('hardware','ipAddress',packet[IP].src).get('_id')
                send_to_api('hardware', hardware_id, data)
            #find hidden iphones
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and packet[DNS].an.type == 16 and 'rdlink' in packet[DNS].an.rrname.decode():
                hostname = packet[DNS].an.rrname.decode()
                hostname = hostname.split(".", 1)[0]
                data = {
                    "ipAddress": packet[IP].src,
                    "macAddress": mac,
                    "hostName": hostname,
                    "lastSeen": datetime.now
                }
                hardware_id = find_obj_by_key('hardware','ipAddress',packet[IP].src).get('_id')
                send_to_api('hardware', hardware_id, data)
                alert(srcip,1005,'[MDNS] discovered new hostname '.format(packet[IP].src,hostname))

    elif packet.haslayer(IP):
        srcip = packet[IP].src
        srcmac = packet[Ether].src
        dstip = packet[IP].dst
        dstmac = packet[Ether].dst

        if is_rfc(srcip): update_host('src','ip',srcip,srcmac,vlanid)
        if is_rfc(dstip): update_host('dest','ip',dstip,dstmac,vlanid)

        proto = ''
        if packet.haslayer(UDP): proto='UDP'
        if packet.haslayer(TCP): proto='TCP'
        if proto != '':
            srcport=packet[proto].sport 
            dstport=packet[proto].dport 
            ip_bytes = packet[IP].original
            time_ms = int(packet[IP].time * 1000) # Convert packet timestamp to milliseconds
            aip = ''
            bip = ''
            aport = ''
            bport = ''
 
            if srcip < dstip:
                k = FLOW_KEY.format(proto, srcip, srcport, dstip, dstport)
            else:
                if srcip == dstip:
                    if srcport <= dstport:
                        aip=srcip
                        bip=dstip
                        aport=srcport
                        bport=dstport
                    else:
                        bip=srcip
                        aip=dstip
                        bport=srcport
                        aport=dstport
                else:
                    bip=srcip
                    aip=dstip
                    bport=srcport
                    aport=dstport

                k = FLOW_KEY.format(proto, aip, aport, bip, bport)

            try:  # Try a Flow update
                flow = flow_cache[k]
                flow.detected_protocol = nDPI.process_packet(flow.ndpi_flow, ip_bytes, time_ms, ffi.NULL)
                flow.pkts += 1
                flow.bytes += len(packet)
            except KeyError:  # New Flow
                flow = Flow()
                flow.ndpi_flow = NDPIFlow()  # We create an nDPIFlow object per Flow
                flow.detected_protocol = nDPI.process_packet(flow.ndpi_flow, ip_bytes, time_ms, ffi.NULL)
                flow.pkts += 1
                flow.bytes += len(packet)
                flow_cache[k] = flow
                if is_rfc(srcip) and is_rfc(dstip):
                    alert(srcip,3006,"[IP] new lateral movement found between {} and {}".format(srcip,dstip))

            if flow.detected_protocol.app_protocol == PROTOCOL_UNKNWON: 
                flow.detected_protocol = nDPI.giveup(flow.ndpi_flow) 


            sql.execute('''
                INSERT INTO flows (src, dst, srcport, dstport, protocol, category, count, bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (src, dst, srcport, dstport)
                DO UPDATE SET count = ?, bytes = ?, protocol = ?, category = ?
            ''', (aip, bip, aport, bport, nDPI.protocol_name(flow.detected_protocol), nDPI.protocol_category_name(flow.detected_protocol), flow.pkts, flow.bytes, flow.pkts, flow.bytes, nDPI.protocol_name(flow.detected_protocol), nDPI.protocol_category_name(flow.detected_protocol)))
            conn.commit()
            alert(srcip,1010,"[NDPI] Detected new flow - {}:{}<->{}:{} Proto: {} Category: {}".format(srcip,srcport,dstip,dstport,nDPI.protocol_name(flow.detected_protocol), nDPI.protocol_category_name(flow.detected_protocol)))

        #os detection using tcp syn signatures from p0f
        if is_rfc(srcip) and packet.haslayer(TCP) and packet[TCP].flags.S:
            tcp_result=fingerprint_tcp(packet)
            if tcp_result.match is not None:
                data = {
                    "ipAddress": packet[IP].src,
                    "macAddress": mac,
                    "os": os,
                    "lastSeen": datetime.now
                }
                hardware_id = find_obj_by_key('hardware','ipAddress',srcip.get('_id')
                send_to_api('hardware', hardware_id, data)
                alert(srcip,1005,'[IP] discovered os type using p0f'.format(srcip,tcp_result.match.record.label.name))


if __name__ == "__main__":
    nDPI = NDPI()  # As simple as that. :)
    print("Using nDPI {}".format(nDPI.revision))
    sniff(store=False, prn=handle_packet)
