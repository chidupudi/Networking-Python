from scapy.all import ARP, Ether, srp, sniff, DNS, IP
import netifaces

def get_network_ip():
    """Retrieve the network IP range (CIDR notation) for ARP scan."""
    iface = netifaces.gateways()["default"][netifaces.AF_INET][1]
    iface_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip = iface_info["addr"]
    netmask = iface_info["netmask"]

    # Calculate CIDR (e.g., 192.168.0.1/24)
    cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
    return f"{ip}/{cidr}"
def scan_network(ip_range):
    """Scan the network for active devices."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices


def packet_callback(packet):
    """Process captured packets to extract DNS queries and application data."""
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
        print(f"DNS Query: {packet[IP].src} -> {packet[DNS].qd.qname.decode()}")
    elif packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"Traffic: {src} -> {dst} ({len(packet)} bytes)")
def monitor_traffic():
    """Start sniffing network traffic."""
    print("Starting traffic monitor...")
    sniff(prn=packet_callback, store=False)  # Sniff packets without storing them in memory
if __name__ == "__main__":
    print("Scanning network...")
    ip_range = get_network_ip()
    devices = scan_network(ip_range)
    print("Connected Devices:")
    for device in devices:
          print(f"IP: {device['ip']}, MAC: {device['mac']}")
    print("\nStarting to monitor traffic. Press Ctrl+C to stop...")
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("\nTraffic monitoring stopped.")
