from typing import Any

packet_db: dict[str, Any] = {}
lan_hosts: dict[str, Any] = {}
destination_hosts: dict[str, Any] = {}
tor_nodes: list[tuple[str, int]] = []
possible_tor_traffic: list[str] = []
possible_mal_traffic: list[str] = []
signatures: dict[str, Any] = {}
