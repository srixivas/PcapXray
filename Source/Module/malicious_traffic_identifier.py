# Custom Module Imports
import memory
import communication_details_fetch
import json, logging, sys
from typing import Any

log = logging.getLogger(__name__)

# Module to Identify Possible Malicious Traffic

class maliciousTrafficIdentifier:

    def __init__(self):
        for session in memory.packet_db:
            src, dst, port = session.split("/")
            if port.isdigit() and self.malicious_traffic_detection(src, dst, int(port)) == 1:
                memory.possible_mal_traffic.append(session)

    def malicious_traffic_detection(self, src: str, dst: str, port: int) -> int:
        well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389, 443]
        # Currently whitelist all the ports
        if not communication_details_fetch.trafficDetailsFetch.is_multicast(src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst):
            if (dst in memory.destination_hosts and memory.destination_hosts[dst].get("domain_name", "NotResolvable") == "NotResolvable") or port > 1024:
                return 1
        return 0

    # TODO: Covert communication module --> Add here
    # * Only add scapy first

    # Covert Detection Algorithm
    @staticmethod
    def covert_traffic_detection(packet: Any) -> int:
        # covert ICMP - icmp tunneling ( Add TCP )
        tunnelled_protocols = ["DNS", "HTTP"]

        # TODO: this does not handle ipv6 --> so check before calling this function
        #if "IP" in packet:
        #    if communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].src) or communication_details_fetch.trafficDetailsFetch.is_multicast(packet["IP"].dst):
        #        return 0

        if "ICMP" in packet:
            if "TCP in ICMP" in packet or "UDP in ICMP" in packet or "DNS" in packet:
                return 1
            elif "padding" in packet:
                return 1
            elif any(x in str(packet["ICMP"].payload) for x in tunnelled_protocols):
                return 1
        elif "DNS" in packet:
            try:
                if communication_details_fetch.trafficDetailsFetch.dns(packet["DNS"].qd.qname.strip()) == "NotResolvable":
                    return 1
                elif sum(c.isdigit() for c in str(packet["DNS"].qd.qname).strip()) > 8:
                    return 1
            except Exception:
                log.debug("covert_traffic_detection: DNS qname parse failed", exc_info=True)
        return 0
    
    
    # Covert payload prediction algorithm
    @staticmethod
    def covert_payload_prediction(payload: Any) -> list[str]:

        ### Magic Number OR File Signature Intelligence
        # Fetch the File Signature OR Magic Numbers Intelligence from the Internet
        # Obtained from the Internet
        #          @ https://gist.github.com/Qti3e/6341245314bf3513abb080677cd1c93b
        #          @ /etc/nginx/mime.types
        #          @ http://www.garykessler.net/library/file_sigs.html
        #          @ https://en.wikipedia.org/wiki/List_of_file_signatures
        #
        try:
            if memory.signatures == {}:
                with open(sys.path[0] + "/magic_numbers.txt") as f:
                    memory.signatures = json.load(f)
            matches = []
            string_payload = str(payload)
            try:
                payload = bytes(payload).hex()
            except Exception:
                payload = string_payload
            for file_type in memory.signatures:
                for sign in memory.signatures[file_type].get("signs", []):
                    try:
                        _, magic = sign.split(",", 1)
                        magic = magic.strip()
                        if magic.lower() in payload or magic in string_payload:
                            matches.append(file_type)
                    except Exception:
                        log.debug("covert_payload_prediction: bad sign entry %r", sign, exc_info=True)
            return matches
        except Exception:
            log.warning("covert_payload_prediction: file signature analysis failed", exc_info=True)
            return []



