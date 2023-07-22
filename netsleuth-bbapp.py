#!/usr/bin/python3

import request;
import time
from ipaddress import ip_address
from scapy.all import *
import logging
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.database import DATABASE
from collections import namedtuple
from ndpi import NDPI, NDPIFlow, ffi

FLOW_KEY = "{} {}:{} <-> {}:{}"
FLOW_STR = "   {} {} [protocol:{}] [category:{}] [confidence:{}] [{} packets/{} bytes]"
PROTOCOL_UNKNWON = 0
flow_cache = {}  # We store the flows in a dictionary.
flow_count = 0  # Flow counter

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

conn = sqlite3.connect('netsleuth.db')
sql = conn.cursor()

sql.execute('''
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        mac TEXT,
        hostname TEXT,
        vendor TEXT,
        os TEXT,
        type TEXT,
        vlan_id INTEGER,
        group_id INTEGER DEFAULT 0,
        total_arp INTEGER DEFAULT 0,
        target_count INTEGER DEFAULT 0,
        total_arp_last_reset INTEGER,
        target_count_last_reset INTEGER,
        last_seen TEXT,
        watch INTEGER DEFAULT 0,
        status INTEGER
    )
''')

sql.execute('''
    CREATE TABLE IF NOT EXISTS vlans (
        id INTEGER PRIMARY KEY,
        name TEXT,
        lowest_ip TEXT,
        highest_ip TEXT,
        mask TEXT,
        router TEXT,
        dns_servers TEXT
    )
''')

sql.execute('''
    CREATE TABLE IF NOT EXISTS flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src TEXT,
        srcport TEXT,
        dst TEXT,
        dstport TEXT, 
        protocol TEXT,
        category TEXT,
        count INTEGER DEFAULT 0,
        bytes INTEGER DEFAULT 0,
        count_last_reset INTEGER DEFAULT 0,
        UNIQUE (src, dst, srcport, dstport)
    )
''')

sql.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        host TEXT,
        event_id TEXT,
        event TEXT
    )
''')



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
    sql.execute('INSERT INTO alerts (timestamp, host, event_id, event) VALUES (?, ?, ?, ?)', (timestamp, ip, event_id, event))
    conn.commit()    

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

    current_time = int(time.time())

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
            sql.execute('''
                INSERT OR IGNORE INTO hosts (ip, mac, vendor, vlan_id, hostname, status, target_count_last_reset, total_arp_last_reset)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (ip, mac, vendor, vlan, hostname, 1, current_time, current_time))
            if sql.rowcount > 0:
                if type == 'arp': alert(ip,1001,"[ARP] new host found: {}".format(ip))
                if type == 'ip': alert(ip,1002,"[IP] new host found: {}".format(ip))
                sql.execute('''
                    UPDATE vlans
                    SET lowest_ip = MIN(COALESCE(lowest_ip, ?), ?),
                    highest_ip = MAX(COALESCE(highest_ip, ?), ?)
                    WHERE id = ?
                ''', (ip, ip, ip, ip, vlan))   
                conn.commit()
 
    sql.execute('''
        UPDATE hosts
        SET last_seen = datetime('now') where ip = ?
        ''', (ip,))
    conn.commit()

    if direction == 'src' and type == 'arp':
        sql.execute('''
            SELECT total_arp,total_arp_last_reset 
            FROM hosts 
            WHERE ip = ?
        ''', (ip,))

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
            sql.execute('''
                UPDATE hosts
                SET total_arp = ?, total_arp_last_reset = ?
                WHERE ip = ?
            ''', (total_arp, total_arp_last_reset, ip))

    if direction == 'dest' and type == 'arp':
        sql.execute('''
            SELECT target_count,target_count_last_reset 
            FROM hosts 
            WHERE ip = ?
        ''', (ip,))

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

            sql.execute('''
                UPDATE hosts
                SET target_count = ?, target_count_last_reset = ?
                WHERE ip = ?
            ''', (target_count, target_count_last_reset, ip))

def handle_packet(packet):
    vlanid = 0
    srcip = 0
    dstip = 0
    current_time = int(time.time())

    if packet.haslayer(Dot1Q):
        vlanid = packet[Dot1Q].vlan

    sql.execute('''
       INSERT OR IGNORE INTO vlans (id)
       VALUES (?)
    ''', (vlanid,))
    if sql.rowcount > 0:
        alert(vlanid,1003,"[VLAN] new VLAN found: {}".format(vlanid))
    conn.commit()

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if packet[Ether].src != packet[ARP].hwsrc:
            srcip = packet[ARP].psrc
            alert(srcip,3010,"[ARP] Spoofed ARP packet detected for {}".format(srcip))

    if packet.haslayer(ARP) and packet[ARP].op == 1:
        srcmac = packet[Ether].src
        srcip = packet[ARP].psrc
        dstip = packet[ARP].pdst

        if is_rfc(srcip): update_host('src','arp',srcip,srcmac,vlanid)
        if is_rfc(dstip): update_host('dest','arp',dstip,'',vlanid)


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
            sql.execute('''
                UPDATE hosts
                SET hostname = ?
                WHERE ip = ? and hostname = 'Unknown'
            ''',(hostname,srcip))
            alert(srcip,1006,'[DHCP] discovered new hostname '.format(srcip,hostname))

        if router:
            sql.execute('''
                UPDATE hosts
                SET type = ?
                WHERE ip = ?
            ''',('router',router))
            sql.execute('''
                UPDATE vlans 
                SET router = ?
                WHERE id = ?
            ''',(router,vlanid))
            alert(srcip,1003,'[DHCP] discovered new router '.format(router))

        if subnet_mask:
            sql.execute('''
                UPDATE vlans 
                SET mask = ?
                WHERE id = ?
            ''',(subnet_mask,vlanid))

    elif packet.haslayer(DNS) and packet.haslayer(UDP):
        if packet[DNS].ancount >=1:
            #if packet.haslayer(IP):
            #    print(packet[IP].src,": ",packet[DNS].an.type," ",packet[DNS].an.rrname.decode())
            # A and AAAA records
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and (packet[DNS].an.type == 1 or packet[DNS].an.type == 28):
                hostname = packet[DNS].an.rrname.decode()
                hostname = hostname.split(".", 1)[0]
                sql.execute('''
                    UPDATE hosts
                    SET hostname = ?
                    WHERE ip = ? and hostname = 'Unknown'
                ''',(hostname,packet[IP].src))
                alert(srcip,1005,'[MDNS] discovered new hostname '.format(packet[IP].src,hostname))
            #find ipp printers
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and packet[DNS].an.type == 16 and 'ipp' in packet[DNS].an.rrname.decode():
                sql.execute('''
                    UPDATE hosts
                    SET type = ?
                    WHERE ip = ?
                ''',('printer',packet[IP].src))
                alert(srcip,1004,'[MDNS] discovered new printer '.format(packet[IP].src))
            #find hidden iphones
            if packet[UDP].sport == 5353 and packet.haslayer(IP) and packet[DNS].an.type == 16 and 'rdlink' in packet[DNS].an.rrname.decode():
                hostname = packet[DNS].an.rrname.decode()
                hostname = hostname.split(".", 1)[0]
                sql.execute('''
                    UPDATE hosts
                    SET hostname = ?
                    WHERE ip = ? and hostname = 'Unknown'
                ''',(hostname,packet[IP].src))
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
                sql.execute('''
                    UPDATE hosts
                    SET os = ?
                    WHERE ip = ?
                ''',(tcp_result.match.record.label.name,srcip))
                alert(srcip,1005,'[IP] discovered os type using p0f'.format(srcip,tcp_result.match.record.label.name))


if __name__ == "__main__":
    nDPI = NDPI()  # As simple as that. :)
    print("Using nDPI {}".format(nDPI.revision))
    sniff(store=False, prn=handle_packet)
