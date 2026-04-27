"""Base types shared by all packet engines."""
from __future__ import annotations

__all__ = ["NormalizedPacket", "PacketEngine"]

from dataclasses import dataclass, field
from typing import Iterator, Protocol, runtime_checkable


@dataclass(slots=True)
class NormalizedPacket:
    ip_version:    int           # 4 or 6
    src_ip:        str
    dst_ip:        str
    src_mac:       str = ""
    dst_mac:       str = ""
    proto:         str = ""      # "TCP" | "UDP" | "ICMP" | ""
    src_port:      int | None = None
    dst_port:      int | None = None
    payload_bytes: bytes = b""
    tls_records:   list[str] = field(default_factory=list)
    dns_qname:     str = ""      # DNS query name, populated for UDP port-53 packets
    icmp_tunneled: bool = False  # True if engine detected tunneled protocol in ICMP


@runtime_checkable
class PacketEngine(Protocol):
    def stream(self) -> Iterator[NormalizedPacket]: ...
