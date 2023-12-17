import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

        if packet.haslayer(scapy.TCP):
            tcp_src_port = packet[scapy.TCP].sport
            tcp_dst_port = packet[scapy.TCP].dport
            print(f"TCP Port: {tcp_src_port} -> {tcp_dst_port}")

            data = packet[scapy.Raw].load
            print(f"Data: {data}")

def start_sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_callback)

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface (e.g., "eth0" for Ethernet, "wlan0" for Wi-Fi)
    start_sniffer(interface)
