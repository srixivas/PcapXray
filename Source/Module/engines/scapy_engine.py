"""Scapy-backed packet engine — streaming PcapReader, TLS-aware."""
__all__ = ["ScapyEngine"]

import logging
from typing import Iterator

from .base import NormalizedPacket

log = logging.getLogger(__name__)

try:
    from scapy.utils import PcapReader
    _scapy_available = True
except ImportError:
    _scapy_available = False
    PcapReader = None  # type: ignore[assignment]

_tls_available = False
if _scapy_available:
    try:
        from scapy.all import load_layer
        load_layer("tls")
        _tls_available = True
    except Exception:
        pass


class ScapyEngine:
    def __init__(self, pcap_path: str) -> None:
        if not _scapy_available:
            raise ImportError("scapy is not installed")
        self._pcap_path = pcap_path
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        log.info("ScapyEngine: TLS=%s, path=%s", _tls_available, pcap_path)

    def stream(self) -> Iterator[NormalizedPacket]:
        count = 0
        with PcapReader(self._pcap_path) as reader:
            for pkt in reader:
                count += 1
                try:
                    norm = _normalize(pkt)
                except Exception as exc:
                    log.debug("ScapyEngine: skipping packet %d: %s", count, exc)
                    continue
                if norm is not None:
                    yield norm
        log.info("ScapyEngine: read %d packets from %s", count, self._pcap_path)


def _normalize(pkt) -> NormalizedPacket | None:
    if "IPv6" in pkt:
        ip = pkt["IPv6"]
        ip_version = 6
    elif "IP" in pkt:
        ip = pkt["IP"]
        ip_version = 4
    else:
        return None

    src_ip, dst_ip = ip.src, ip.dst

    src_mac = dst_mac = ""
    if "Ether" in pkt:
        src_mac = pkt["Ether"].src
        dst_mac = pkt["Ether"].dst

    proto = ""
    src_port: int | None = None
    dst_port: int | None = None
    payload_bytes: bytes = b""
    tls_records: list[str] = []
    dns_qname = ""
    icmp_tunneled = False

    if "TCP" in pkt:
        proto = "TCP"
        src_port = int(pkt["TCP"].sport)
        dst_port = int(pkt["TCP"].dport)
        payload_bytes, tls_records = _tcp_payload(pkt)

    elif "UDP" in pkt:
        proto = "UDP"
        src_port = int(pkt["UDP"].sport)
        dst_port = int(pkt["UDP"].dport)
        try:
            payload_bytes = bytes(pkt["UDP"].payload)
        except Exception:
            payload_bytes = b""
        if "DNS" in pkt:
            try:
                # qd is a PacketListField in scapy >= 2.5; access first element
                qd = pkt["DNS"].qd
                raw = qd[0].qname if hasattr(qd, "__getitem__") else qd.qname
                dns_qname = (raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else str(raw)).rstrip(".")
            except Exception:
                pass

    elif "ICMP" in pkt:
        proto = "ICMP"
        try:
            payload_bytes = bytes(pkt["ICMP"].payload)
        except Exception:
            payload_bytes = b""
        icmp_tunneled = (
            "TCP in ICMP" in pkt
            or "UDP in ICMP" in pkt
            or "DNS" in pkt
            or "padding" in pkt
            or any(x in str(pkt["ICMP"].payload) for x in ("DNS", "HTTP"))
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
        tls_records=tls_records,
        dns_qname=dns_qname,
        icmp_tunneled=icmp_tunneled,
    )


def _tcp_payload(pkt) -> tuple[bytes, list[str]]:
    if _tls_available:
        for layer in ("TLS", "SSLv2", "SSLv3"):
            if layer in pkt:
                try:
                    return b"", [str(pkt[layer].msg)]
                except Exception:
                    break
    try:
        return bytes(pkt["TCP"].payload), []
    except Exception:
        return b"", []
