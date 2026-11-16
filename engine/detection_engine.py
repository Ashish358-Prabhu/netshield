
from collections import defaultdict
import requests


API_URL = "http://127.0.0.1:8000/alerts"


def detect_suspicious_activity(packets):
    alerts = []
    source_data = defaultdict(list)

    # Group packets by source IP
    for packet in packets:
        source_data[packet["src_ip"]].append(packet)

    # Analyze each source IP
    for source_ip, records in source_data.items():

        # Rule 1: Detect possible port scanning
        destination_ports = {
            p["dst_port"]
            for p in records
            if p["dst_port"] is not None
        }

        if len(destination_ports) >= 20:
            alerts.append({
                "source_ip": source_ip,
                "type": "Possible Port Scan",
                "severity": "High",
                "description": (
                    f"Contacted {len(destination_ports)} "
                    "different destination ports"
                )
            })

        # Rule 2: Detect traffic spikes
        if len(records) >= 100:
            alerts.append({
                "source_ip": source_ip,
                "type": "Traffic Spike",
                "severity": "Medium",
                "description": (
                    f"Generated {len(records)} packets"
                )
            })

        # Rule 3: Detect repeated TCP SYN packets
        syn_packets = [
            p for p in records
            if p["protocol"] == "TCP"
            and p["tcp_flags"] is not None
            and "S" in p["tcp_flags"]
            and "A" not in p["tcp_flags"]
        ]

        if len(syn_packets) >= 30:
            alerts.append({
                "source_ip": source_ip,
                "type": "Repeated SYN Attempts",
                "severity": "High",
                "description": (
                    f"Generated {len(syn_packets)} "
                    "TCP SYN packets"
                )
            })

    return alerts


def save_alert_to_api(alert):
    # Convert detection alert into API format
    payload = {
        "alert_type": alert["type"],
        "source_ip": alert["source_ip"],
        "severity": alert["severity"],
        "description": alert["description"]
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=5
        )

        response.raise_for_status()

        result = response.json()
        print(
            f"Successfully saved alert! "
            f"Database ID: {result['alert_id']}"
        )

    except requests.RequestException as error:
        print(f"Could not save alert: {error}")


if __name__ == "__main__":

    from packet_capture import analyze_pcap

    packets = analyze_pcap("datasets/sample.pcap")

    alerts = detect_suspicious_activity(packets)

    print("\n========== NETSHIELD ALERTS ==========")

    if not alerts:
        print("No suspicious activity detected.")

    for alert in alerts:

        print("\nAlert:", alert["type"])
        print("Source IP:", alert["source_ip"])
        print("Severity:", alert["severity"])
        print("Description:", alert["description"])

        # Automatically save alert to SQLite through FastAPI
        save_alert_to_api(alert)
