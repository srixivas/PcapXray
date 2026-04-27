"""
Module pcap_reader
"""
__all__ = ["PcapEngine"]

import concurrent.futures
import ipaddress
import logging
import sys

import memory
from memory import PacketSession, LanHost, DestinationHost
from engines import NormalizedPacket, select_engine
import communication_details_fetch
import malicious_traffic_identifier

log = logging.getLogger(__name__)


class PcapEngine:
    """Reads a PCAP file and populates memory.* state.

    engine_name: "auto" (default), "dpkt", "scapy", or "pyshark"
    """

    def __init__(self, pcap_file_name: str, pcap_parser_engine: str = "auto") -> None:
        memory.packet_db = {}
        memory.lan_hosts = {}
        memory.destination_hosts = {}
        memory.possible_mal_traffic = []
        memory.possible_tor_traffic = []

        self.engine = pcap_parser_engine
        # session_key → DNS qname, for deferred covert resolution
        self._dns_candidates: dict[str, str] = {}

        try:
            engine = select_engine(pcap_parser_engine, pcap_file_name)
        except (ImportError, ValueError) as exc:
            log.error("Cannot create engine %r: %s", pcap_parser_engine, exc)
            sys.exit(1)

        log.info("Reading PCAP: %s (engine=%s)", pcap_file_name, pcap_parser_engine)
        self._build_sessions(engine)
        self._run_deferred_covert()
        log.info(
            "PCAP analysis complete: %d sessions, %d LAN hosts, %d dest hosts",
            len(memory.packet_db), len(memory.lan_hosts), len(memory.destination_hosts),
        )

    # ------------------------------------------------------------------
    # Session builder — engine-agnostic, consumes NormalizedPacket stream
    # ------------------------------------------------------------------

    def _build_sessions(self, engine) -> None:
        for pkt in engine.stream():
            try:
                self._process_packet(pkt)
            except Exception as exc:
                log.debug("_build_sessions: skipping packet: %s", exc)

    def _process_packet(self, pkt: NormalizedPacket) -> None:
        try:
            private_source = ipaddress.ip_address(pkt.src_ip).is_private
        except Exception:
            private_source = None
        try:
            private_destination = ipaddress.ip_address(pkt.dst_ip).is_private
        except Exception:
            private_destination = None

        session_key: str | None = None

        if pkt.proto in ("TCP", "UDP"):
            src_p = str(pkt.src_port or 0)
            dst_p = str(pkt.dst_port or 0)

            if private_source and private_destination:
                key1 = f"{pkt.src_ip}/{pkt.dst_ip}/{dst_p}"
                key2 = f"{pkt.dst_ip}/{pkt.src_ip}/{src_p}"
                session_key = key2 if key2 in memory.packet_db else key1
                if pkt.src_mac:
                    if pkt.src_mac not in memory.lan_hosts:
                        memory.lan_hosts[pkt.src_mac] = LanHost(ip=pkt.src_ip)
                    if pkt.dst_mac not in memory.lan_hosts:
                        memory.lan_hosts[pkt.dst_mac] = LanHost(ip=pkt.dst_ip)

            elif private_source:
                session_key = f"{pkt.src_ip}/{pkt.dst_ip}/{dst_p}"
                if pkt.src_mac:
                    if pkt.src_mac not in memory.lan_hosts:
                        memory.lan_hosts[pkt.src_mac] = LanHost(ip=pkt.src_ip)
                    if pkt.dst_ip not in memory.destination_hosts:
                        memory.destination_hosts[pkt.dst_ip] = DestinationHost(mac=pkt.dst_mac)

            elif private_destination:
                session_key = f"{pkt.dst_ip}/{pkt.src_ip}/{src_p}"
                if pkt.dst_mac:
                    if pkt.dst_mac not in memory.lan_hosts:
                        memory.lan_hosts[pkt.dst_mac] = LanHost(ip=pkt.dst_ip)
                    if pkt.src_ip not in memory.destination_hosts:
                        memory.destination_hosts[pkt.src_ip] = DestinationHost(mac=pkt.src_mac)

            else:  # both public
                key1 = f"{pkt.src_ip}/{pkt.dst_ip}/{dst_p}"
                key2 = f"{pkt.dst_ip}/{pkt.src_ip}/{src_p}"
                session_key = key2 if key2 in memory.packet_db else key1
                if pkt.src_mac:
                    if pkt.src_ip not in memory.destination_hosts:
                        memory.destination_hosts[pkt.src_ip] = DestinationHost(mac=pkt.src_mac)
                    if pkt.dst_ip not in memory.destination_hosts:
                        memory.destination_hosts[pkt.dst_ip] = DestinationHost(mac=pkt.dst_mac)

        elif pkt.proto == "ICMP":
            key1 = f"{pkt.src_ip}/{pkt.dst_ip}/ICMP"
            key2 = f"{pkt.dst_ip}/{pkt.src_ip}/ICMP"
            session_key = key2 if key2 in memory.packet_db else key1

        if session_key is None:
            return

        if session_key not in memory.packet_db:
            memory.packet_db[session_key] = PacketSession()
        session = memory.packet_db[session_key]

        # Ethernet + direction (LAN-centric: "src" is always the LAN host's MAC)
        if private_source:
            if pkt.src_mac:
                session.Ethernet["src"] = pkt.src_mac
                session.Ethernet["dst"] = pkt.dst_mac
            direction = "forward"
        else:
            if pkt.dst_mac:
                session.Ethernet["src"] = pkt.dst_mac
                session.Ethernet["dst"] = pkt.src_mac
            direction = "reverse"

        # Payload
        if pkt.tls_records:
            session.Payload[direction].extend(pkt.tls_records)
            payload_for_sig: bytes = b""
        elif pkt.payload_bytes:
            session.Payload[direction].append(
                pkt.payload_bytes.decode("latin-1", errors="replace")
            )
            payload_for_sig = pkt.payload_bytes
        else:
            payload_for_sig = b""

        # Covert detection — inline tier (no I/O)
        src, dst, _port = session_key.split("/")
        if not session.covert:
            if (not communication_details_fetch.TrafficDetailsFetch.is_multicast(src)
                    and not communication_details_fetch.TrafficDetailsFetch.is_multicast(dst)):
                if pkt.proto == "ICMP" and pkt.icmp_tunneled:
                    session.covert = True
                elif pkt.dns_qname:
                    if sum(c.isdigit() for c in pkt.dns_qname) > 8:
                        session.covert = True
                    elif session_key not in self._dns_candidates:
                        self._dns_candidates[session_key] = pkt.dns_qname

        # Covert file signature scan (only once session is flagged covert)
        if payload_for_sig and session.covert:
            signs = malicious_traffic_identifier.MaliciousTrafficIdentifier.covert_payload_prediction(
                payload_for_sig
            )
            if signs:
                session.file_signatures = list(set(session.file_signatures + signs))

    # ------------------------------------------------------------------
    # Deferred covert detection — batch DNS resolution post-loop
    # ------------------------------------------------------------------

    def _run_deferred_covert(self) -> None:
        if not self._dns_candidates:
            return

        # Deduplicate qnames to avoid resolving the same name multiple times
        qname_to_keys: dict[str, list[str]] = {}
        for key, qname in self._dns_candidates.items():
            qname_to_keys.setdefault(qname, []).append(key)

        log.info("Deferred covert check: %d unique qnames", len(qname_to_keys))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = {
                pool.submit(communication_details_fetch.TrafficDetailsFetch.dns, q): q
                for q in qname_to_keys
            }
            done, not_done = concurrent.futures.wait(futures, timeout=10.0)
            for f in not_done:
                f.cancel()
            for f in done:
                qname = futures[f]
                try:
                    result = f.result()
                except Exception:
                    result = "NotResolvable"
                if result == "NotResolvable":
                    for key in qname_to_keys[qname]:
                        if key in memory.packet_db:
                            memory.packet_db[key].covert = True
                            log.debug("Deferred covert: %s (qname=%s)", key, qname)

        log.info("Deferred covert check complete")
