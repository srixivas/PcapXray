import memory 

# Library Import
import ipwhois
#from dns import reversename, resolver
import socket
# Module Import
#import pcap_reader
import netaddr

# Class Communication or Traffic Details Fetch

class trafficDetailsFetch():

    def __init__(self, option):
        for host in memory.destination_hosts:
            if "domain_name" not in memory.destination_hosts[host]:
                if option == "whois":
                    memory.destination_hosts[host]["domain_name"] = self.whois_info_fetch(host)
                else:
                    memory.destination_hosts[host]["domain_name"] = trafficDetailsFetch.dns(host)

    def whois_info_fetch(self, ip):
        try:
           whois_info = ipwhois.IPWhois(ip).lookup_rdap()
        except Exception:
           whois_info = "NoWhoIsInfo"
        return whois_info
    
    """
    @staticmethod
    def dns_using_library(ip):
        try:
            reverse_query = reversename.from_address(ip)
            resolve_bot = resolve.Resolver()
            resolve_bot.timeout = 1
            resolve_bot.lifetime = 1
            dns_info = str(resolve_bot.query(reverse_query,"PTR")[0])
        except:
            dns_info = "NotResolvable"
        return dns_info
    """

    @staticmethod
    def dns(ip):
        try:
            dns_info = socket.gethostbyaddr(ip)[0]
        except OSError:
            dns_info = "NotResolvable"
        return dns_info

    @staticmethod
    def is_multicast(ip):
        if ":" in ip:
            groups = ip.split(":")
            if "FF0" in groups[0].upper():
                return True
        else:
            octets = ip.split(".")
            if int(octets[0]) >= 224:
                return True
        return False

def main():
    import pcap_reader
    capture = pcap_reader.PcapEngine('examples/test.pcap', "scapy")
    details = trafficDetailsFetch("sock")
    print(memory.destination_hosts)
    print("\n")

#main()
