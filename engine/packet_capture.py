
from scapy.all import IP, TCP, UDP, ICMP
from scapy.utils import PcapReader
import sys


def analyze_pcap(file_path):
    packets_data = []

    with PcapReader(file_path) as packets:
        for packet in packets:

            if IP not in packet:
                continue

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol = "OTHER"
            source_port = None
            destination_port = None
            tcp_flags = None

            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)

            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            elif ICMP in packet:
                protocol = "ICMP"

            packet_info = {
                "timestamp": float(packet.time),
                "src_ip": source_ip,
                "dst_ip": destination_ip,
                "src_port": source_port,
                "dst_port": destination_port,
                "protocol": protocol,
                "size": len(packet),
                "tcp_flags": tcp_flags
            }

            packets_data.append(packet_info)

    return packets_data


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python packet_capture.py <pcap_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    data = analyze_pcap(file_path)

    print("Total packets analyzed:", len(data))

    for packet in data[:10]:
        print(packet)
