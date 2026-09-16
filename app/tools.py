from __future__ import annotations

from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, PcapReader, Raw, sniff


PROTOCOLS = ("IP", "TCP", "UDP", "ICMP", "ARP", "DNS")


def _packet_record(packet: Any) -> dict[str, Any]:
    ip_layer = packet.getlayer(IP)
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    return {
        "time": datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S"),
        "source": getattr(ip_layer, "src", getattr(packet.getlayer(ARP), "psrc", "-")),
        "destination": getattr(ip_layer, "dst", getattr(packet.getlayer(ARP), "pdst", "-")),
        "protocol": "DNS" if packet.haslayer(DNS) else next((name for name, layer in (("TCP", TCP), ("UDP", UDP), ("ICMP", ICMP), ("ARP", ARP)) if packet.haslayer(layer)), "IP"),
        "length": len(packet),
        "port": getattr(transport, "dport", None),
        "flags": str(getattr(transport, "flags", "")) if transport else "",
    }


def _result(packets: list[Any], source: str) -> dict[str, Any]:
    records = [_packet_record(packet) for packet in packets]
    protocol_counts = Counter(record["protocol"] for record in records)
    source_counts = Counter(record["source"] for record in records if record["source"] != "-")
    suspicious = []
    for source_ip, count in source_counts.items():
        if count >= 20:
            suspicious.append({"type": "high_volume_source", "source": source_ip, "evidence": f"{count} packets observed"})
    syn_count = sum(1 for record in records if "S" in record["flags"] and "A" not in record["flags"])
    if syn_count >= 10:
        suspicious.append({"type": "possible_scan", "evidence": f"{syn_count} unanswered SYN candidates"})
    return {
        "source": source,
        "packet_count": len(records),
        "protocols": [{"name": key, "count": protocol_counts.get(key, 0)} for key in PROTOCOLS if protocol_counts.get(key, 0)],
        "top_talkers": [{"address": key, "count": value} for key, value in source_counts.most_common(5)],
        "suspicious": suspicious,
        "packets": records[-100:],
    }


def capture_packets(count: int = 30, interface: str | None = None, timeout: int = 5) -> dict[str, Any]:
    packets = sniff(count=max(1, min(count, 200)), iface=interface or None, timeout=max(1, min(timeout, 30)), store=True)
    return _result(list(packets), "live capture")


def analyze_pcap(path: Path) -> dict[str, Any]:
    with PcapReader(str(path)) as reader:
        packets = list(reader)
    return _result(packets, path.name)


def filter_packets(path: Path, expression: str) -> dict[str, Any]:
    allowed = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "arp": ARP, "dns": DNS, "ip": IP}
    layer = allowed.get(expression.lower().strip())
    if layer is None:
        raise ValueError("Filter must be one of: IP, TCP, UDP, ICMP, ARP, DNS")
    with PcapReader(str(path)) as reader:
        packets = [packet for packet in reader if packet.haslayer(layer)]
    return _result(packets, f"{path.name} / {expression.upper()}")


def authorized_probe(target: str, authorized: bool) -> dict[str, Any]:
    if not authorized:
        raise PermissionError("Active testing requires explicit authorization in the request.")
    address = ip_address(target)
    if not (address.is_private or address.is_loopback):
        raise PermissionError("Active testing is restricted to private or loopback lab targets.")
    return {"target": target, "status": "planned", "action": "No packet sent. Add a lab-specific probe tool here after review."}
