import memory
import ipwhois
import socket
import netaddr
import logging
import concurrent.futures

log = logging.getLogger(__name__)

_DNS_TIMEOUT = 2.0       # seconds per lookup (socket timeout hint — may be ignored on macOS)
_DNS_WORKERS = 30        # parallel reverse-DNS threads
_DNS_TOTAL_TIMEOUT = 10.0  # hard wall-clock cap for the entire batch

class trafficDetailsFetch():

    def __init__(self, option: str) -> None:
        hosts = [h for h in memory.destination_hosts if "domain_name" not in memory.destination_hosts[h]]
        log.info("DNS resolution start: %d hosts, option=%s", len(hosts), option)
        resolve = self.whois_info_fetch if option == "whois" else trafficDetailsFetch.dns
        with concurrent.futures.ThreadPoolExecutor(max_workers=_DNS_WORKERS) as pool:
            future_map = {pool.submit(resolve, h): h for h in hosts}
            done, not_done = concurrent.futures.wait(future_map, timeout=_DNS_TOTAL_TIMEOUT)

            for future in not_done:
                future.cancel()
                memory.destination_hosts[future_map[future]]["domain_name"] = "NotResolvable"
                log.debug("DNS timeout: %s", future_map[future])

            for future in done:
                host = future_map[future]
                try:
                    memory.destination_hosts[host]["domain_name"] = future.result()
                    log.debug("Resolved %s → %s", host, memory.destination_hosts[host]["domain_name"])
                except Exception:
                    memory.destination_hosts[host]["domain_name"] = "NotResolvable"

        log.info("DNS resolution complete: %d resolved, %d timed out", len(done), len(not_done))

    def whois_info_fetch(self, ip: str) -> str:
        try:
            result = ipwhois.IPWhois(ip).lookup_rdap()
            return result.get("asn_description", "NoWhoIsInfo")
        except Exception:
            return "NoWhoIsInfo"

    @staticmethod
    def dns(ip: str) -> str:
        # Save/restore to avoid permanently changing the global socket timeout
        prev = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(_DNS_TIMEOUT)
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return "NotResolvable"
        finally:
            socket.setdefaulttimeout(prev)

    @staticmethod
    def is_multicast(ip: str) -> bool:
        if ":" in ip:
            groups = ip.split(":")
            if "FF0" in groups[0].upper():
                return True
        else:
            octets = ip.split(".")
            if int(octets[0]) >= 224:
                return True
        return False

