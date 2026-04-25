from typing import Any
from pydantic import BaseModel, Field

__all__ = [
    "PacketSession", "LanHost", "DestinationHost",
    "packet_db", "lan_hosts", "destination_hosts",
    "tor_nodes", "possible_tor_traffic", "possible_mal_traffic", "signatures",
]


class PacketSession(BaseModel):
    Ethernet: dict[str, str] = Field(default_factory=lambda: {"src": "", "dst": ""})
    Payload: dict[str, list[str]] = Field(default_factory=lambda: {"forward": [], "reverse": []})
    covert: bool = False
    file_signatures: list[str] = []


class LanHost(BaseModel):
    ip: str
    device_vendor: str = "Unknown"
    vendor_address: str = "Unknown"
    node: str = ""


class DestinationHost(BaseModel):
    mac: str = ""
    domain_name: str = ""
    device_vendor: str = "Unknown"


# Global state containers — keyed by "src/dst/port" session strings
packet_db: dict[str, PacketSession] = {}
lan_hosts: dict[str, LanHost] = {}
destination_hosts: dict[str, DestinationHost] = {}
tor_nodes: list[tuple[str, int]] = []
possible_tor_traffic: list[str] = []
possible_mal_traffic: list[str] = []
signatures: dict[str, Any] = {}
