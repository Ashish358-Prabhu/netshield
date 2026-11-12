
from collections import defaultdict, deque


def track_flows(packets, window_seconds=60):

    flows = defaultdict(lambda: {
        "packet_count": 0,
        "total_bytes": 0,
        "first_seen": None,
        "last_seen": None
    })

    source_activity = defaultdict(deque)

    for packet in packets:

        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        protocol = packet["protocol"]
        timestamp = packet["timestamp"]

        # Identify a network flow using its five-tuple
        flow_key = (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        flow = flows[flow_key]

        flow["packet_count"] += 1
        flow["total_bytes"] += packet["size"]

        if flow["first_seen"] is None:
            flow["first_seen"] = timestamp

        flow["last_seen"] = timestamp

        # Track recent activity from each source IP
        activity = source_activity[src_ip]
        activity.append({
            "timestamp": timestamp,
            "dst_port": dst_port,
            "size": packet["size"]
        })

        # Remove entries older than the time window
        while activity and timestamp - activity[0]["timestamp"] > window_seconds:
            activity.popleft()

    return flows, source_activity


if __name__ == "__main__":

    from packet_capture import analyze_pcap

    packets = analyze_pcap("datasets/sample.pcap")

    flows, source_activity = track_flows(packets)

    print("Total network flows:", len(flows))

    for key, value in flows.items():
        print("\nFlow:", key)
        print("Packets:", value["packet_count"])
        print("Total bytes:", value["total_bytes"])

    print("\nSource activity:")

    for source_ip, activity in source_activity.items():
        print(source_ip, "Packets:", len(activity))

