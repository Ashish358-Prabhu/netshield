
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

packets = []

# 1. Normal TCP traffic
for i in range(10):
    packet = (
        IP(src="192.168.1.10", dst="203.0.113.10") /
        TCP(sport=5000 + i, dport=80, flags="PA") /
        Raw(load="NetShield test packet")
    )
    packets.append(packet)

# 2. Normal UDP traffic
for i in range(5):
    packet = (
        IP(src="192.168.1.10", dst="203.0.113.20") /
        UDP(sport=6000 + i, dport=53) /
        Raw(load="DNS test data")
    )
    packets.append(packet)

# 3. ICMP traffic
for i in range(5):
    packet = (
        IP(src="192.168.1.10", dst="203.0.113.30") /
        ICMP()
    )
    packets.append(packet)

# 4. Simulated port scanning pattern
for port in range(20, 51):
    packet = (
        IP(src="192.168.1.50", dst="203.0.113.40") /
        TCP(sport=7000, dport=port, flags="S")
    )
    packets.append(packet)

# Save packets into a PCAP file
wrpcap("datasets/sample.pcap", packets)

print("Sample PCAP dataset generated successfully!")
print("Total packets:", len(packets))
