"""
Module device_details
"""
# Library Import
import urllib.request
import json
import logging
import memory
from netaddr import *

class fetchDeviceDetails:

    def __init__(self, option="ieee"):
        """
        Init
        """
        self.target_oui_database = option

    def fetch_info(self) -> None:
        for host in memory.lan_hosts:
            mac = host.split("/")[0]
            if self.target_oui_database == "api":
                memory.lan_hosts[host]["device_vendor"] = self.oui_identification_via_api(mac)
            else:
                memory.lan_hosts[host]["device_vendor"], memory.lan_hosts[host]["vendor_address"] = self.oui_identification_via_ieee(mac)
            mac_san = mac.replace(":",".")
            if ":" in memory.lan_hosts[host]["ip"]:
                ip_san = memory.lan_hosts[host]["ip"].replace(":",".")
            else:
                ip_san = memory.lan_hosts[host]["ip"]
            memory.lan_hosts[host]["node"] = ip_san+"\n"+mac_san+"\n"+memory.lan_hosts[host]['device_vendor']

    def oui_identification_via_api(self, mac: str) -> str:
        url = "http://macvendors.co/api/" + mac
        api_request = urllib.request.Request(url, headers={'User-Agent':'PcapXray'})
        try:
            apiResponse = urllib.request.urlopen(api_request)
            details = json.loads(apiResponse.read())
            #reportThread = threading.Thread(target=reportGen.reportGen().deviceDetailsReport,args=(details,))
            #reportThread.start()
            return details["result"]["company"], details["result"]["address"]
        except Exception as e:
            logging.info("device_details module: oui identification failure via api" + str(e))
            return "Unknown", "Unknown"

    def oui_identification_via_ieee(self, mac: str) -> tuple[str, str]:
        try:
            mac_obj = EUI(mac)
            mac_oui = mac_obj.oui
            return mac_oui.registration().org, mac_oui.registration().address
        except Exception as e:
            logging.info("device_details module: oui identification failure via ieee " + str(e))
            return "Unknown", "Unknown"

def main():
    import pcap_reader
    filename = "test.pcap"
    pcap_reader.PcapEngine('examples/test.pcap', "scapy")
    fetchDeviceDetails("ieee").fetch_info()
    print(memory.lan_hosts)

#main()

# MAC Oui Identification Module
# LAN IP and Getway Identification
