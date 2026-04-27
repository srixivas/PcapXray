"""dpkt-backed packet engine — fast, low-memory, offline only."""
__all__ = ["DpktEngine"]

import logging
import socket
from typing import Iterator

from .base import NormalizedPacket

log = logging.getLogger(__name__)

try:
    import dpkt
    _dpkt_available = True
except ImportError:
    _dpkt_available = False
    dpkt = None  # type: ignore[assignment]


class DpktEngine:
    def __init__(self, pcap_path: str) -> None:
        if not _dpkt_available:
            raise ImportError("dpkt is not installed")
        self._pcap_path = pcap_path
        log.info("DpktEngine: path=%s", pcap_path)

    def stream(self) -> Iterator[NormalizedPacket]:
        count = 0
        with open(self._pcap_path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)
            for _ts, buf in reader:
                count += 1
                try:
                    norm = _normalize(buf)
                except Exception as exc:
                    log.debug("DpktEngine: skipping packet %d: %s", count, exc)
                    continue
                if norm is not None:
                    yield norm
        log.info("DpktEngine: read %d packets from %s", count, self._pcap_path)


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _normalize(buf: bytes) -> NormalizedPacket | None:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    src_mac = _mac_str(eth.src) if isinstance(eth.src, bytes) else ""
    dst_mac = _mac_str(eth.dst) if isinstance(eth.dst, bytes) else ""

    ip_pkt = eth.data
    if isinstance(ip_pkt, dpkt.ip.IP):
        ip_version = 4
        src_ip = socket.inet_ntoa(ip_pkt.src)
        dst_ip = socket.inet_ntoa(ip_pkt.dst)
    elif isinstance(ip_pkt, dpkt.ip6.IP6):
        ip_version = 6
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.dst)
    else:
        return None

    transport = ip_pkt.data
    proto = ""
    src_port: int | None = None
    dst_port: int | None = None
    payload_bytes: bytes = b""
    dns_qname = ""
    icmp_tunneled = False

    if isinstance(transport, dpkt.tcp.TCP):
        proto = "TCP"
        src_port = transport.sport
        dst_port = transport.dport
        payload_bytes = bytes(transport.data) if transport.data else b""

    elif isinstance(transport, dpkt.udp.UDP):
        proto = "UDP"
        src_port = transport.sport
        dst_port = transport.dport
        payload_bytes = bytes(transport.data) if transport.data else b""
        if transport.dport == 53 and payload_bytes:
            try:
                dns = dpkt.dns.DNS(payload_bytes)
                if dns.qd:
                    dns_qname = dns.qd[0].name
            except Exception:
                pass

    elif isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        proto = "ICMP"
        payload_bytes = bytes(transport.data) if transport.data else b""
        # Detect IP-in-ICMP (tunneling) by checking if payload starts with IP header
        if payload_bytes:
            icmp_tunneled = (
                (len(payload_bytes) >= 1 and (payload_bytes[0] >> 4) in (4, 6))
                or b"HTTP" in payload_bytes
                or b"GET " in payload_bytes
                or b"POST " in payload_bytes
            )

    return NormalizedPacket(
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        payload_bytes=payload_bytes,
        dns_qname=dns_qname,
        icmp_tunneled=icmp_tunneled,
    )
