"""Pluggable packet engine registry."""
__all__ = ["NormalizedPacket", "PacketEngine", "select_engine"]

from .base import NormalizedPacket, PacketEngine
from .scapy_engine import ScapyEngine
from .dpkt_engine import DpktEngine
from .pyshark_engine import PySharkEngine


def select_engine(name: str, pcap_path: str) -> PacketEngine:
    """Return an engine instance for *name*, falling back gracefully.

    "auto"    — dpkt if available, else scapy
    "dpkt"    — DpktEngine (raises ImportError if dpkt not installed)
    "scapy"   — ScapyEngine
    "pyshark" — PySharkEngine
    """
    if name == "auto":
        try:
            return DpktEngine(pcap_path)
        except ImportError:
            return ScapyEngine(pcap_path)
    if name == "dpkt":
        return DpktEngine(pcap_path)
    if name == "scapy":
        return ScapyEngine(pcap_path)
    if name == "pyshark":
        return PySharkEngine(pcap_path)
    raise ValueError(f"Unknown engine: {name!r}")
