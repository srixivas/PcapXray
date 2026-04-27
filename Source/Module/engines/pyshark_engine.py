"""PyShark-backed packet engine — tshark-based, live-capture ready (Phase 2)."""
__all__ = ["PySharkEngine"]

import logging
from typing import Iterator

from .base import NormalizedPacket

log = logging.getLogger(__name__)

try:
    import pyshark
    _pyshark_available = True
except ImportError:
    _pyshark_available = False
    pyshark = None  # type: ignore[assignment]


class PySharkEngine:
    def __init__(self, pcap_path: str) -> None:
        if not _pyshark_available:
            raise ImportError("pyshark is not installed")
        self._pcap_path = pcap_path
        log.info("PySharkEngine: path=%s", pcap_path)

    def stream(self) -> Iterator[NormalizedPacket]:
        count = 0
        cap = pyshark.FileCapture(self._pcap_path, include_raw=True, use_json=True)
        try:
            for pkt in cap:
                count += 1
                try:
                    norm = _normalize(pkt)
                except Exception as exc:
                    log.debug("PySharkEngine: skipping packet %d: %s", count, exc)
                    continue
                if norm is not None:
                    yield norm
        finally:
            cap.close()
        log.info("PySharkEngine: read %d packets from %s", count, self._pcap_path)


def _normalize(pkt) -> NormalizedPacket | None:
    # pyshark uses uppercase layer names in [] access; lowercase attribute access also works
    if "IPV6" in pkt:
        src_ip = str(pkt["IPV6"].src)
        dst_ip = str(pkt["IPV6"].dst)
        ip_version = 6
    elif "IP" in pkt:
        src_ip = str(pkt["IP"].src)
        dst_ip = str(pkt["IP"].dst)
        ip_version = 4
    else:
        return None

    src_mac = dst_mac = ""
    if "ETH" in pkt:
        src_mac = str(pkt["ETH"].src)
        dst_mac = str(pkt["ETH"].dst)

    proto = ""
    src_port: int | None = None
    dst_port: int | None = None
    payload_bytes: bytes = b""
    dns_qname = ""
    icmp_tunneled = False

    if "TCP" in pkt:
        proto = "TCP"
        try:
            src_port = int(pkt["TCP"].srcport)
            dst_port = int(pkt["TCP"].dstport)
        except Exception:
            pass
        try:
            payload_bytes = pkt.get_raw_packet()
        except Exception:
            payload_bytes = b""

    elif "UDP" in pkt:
        proto = "UDP"
        try:
            src_port = int(pkt["UDP"].srcport)
            dst_port = int(pkt["UDP"].dstport)
        except Exception:
            pass
        try:
            payload_bytes = pkt.get_raw_packet()
        except Exception:
            payload_bytes = b""
        if "DNS" in pkt:
            try:
                dns_qname = str(pkt["DNS"].qry_name)
            except Exception:
                pass

    elif "ICMP" in pkt:
        proto = "ICMP"
        layer_names = {layer.layer_name.upper() for layer in pkt.layers}
        icmp_tunneled = bool(layer_names & {"TCP", "UDP", "IP", "DNS"} - {"ICMP"})

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
