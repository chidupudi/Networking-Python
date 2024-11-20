from scapy.all import sniff, IP, TCP, UDP, wrpcap
from collections import Counter

# Counter for protocol statistics
packet_counts = Counter()

# List to store captured packets
captured_packets = []

# Packet handler function
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        # Update the protocol counter
        packet_counts[protocol] += 1
        
        # Append the packet to the list
        captured_packets.append(packet)
        
        # Print packet details
        print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
        print(f"Packet Counts: {dict(packet_counts)}")

# Main function to start the sniffer
def start_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=packet_handler, count=20)  # Capture 20 packets
    
    # Save packets to a pcap file
    wrpcap("captured_packets.pcap", captured_packets)
    print("Packets saved to 'captured_packets.pcap'")

if __name__ == "__main__":
    start_sniffer()
