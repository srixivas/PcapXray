"""
Module device_details
"""
# Library Import
import urllib.request
import json
import logging
import memory
from netaddr import *

__all__ = ["fetchDeviceDetails"]

log = logging.getLogger(__name__)

class fetchDeviceDetails:

    def __init__(self, option="ieee"):
        """
        Init
        """
        self.target_oui_database = option

    def fetch_info(self) -> None:
        for host in memory.lan_hosts:
            mac = host.split("/")[0]
            h = memory.lan_hosts[host]
            if self.target_oui_database == "api":
                h.device_vendor = self.oui_identification_via_api(mac)
            else:
                h.device_vendor, h.vendor_address = self.oui_identification_via_ieee(mac)
            mac_san = mac.replace(":", ".")
            ip_san = h.ip.replace(":", ".") if ":" in h.ip else h.ip
            h.node = ip_san + "\n" + mac_san + "\n" + h.device_vendor

    def oui_identification_via_api(self, mac: str) -> str:
        url = "https://macvendors.co/api/" + mac
        api_request = urllib.request.Request(url, headers={'User-Agent':'PcapXray'})
        try:
            apiResponse = urllib.request.urlopen(api_request)
            details = json.loads(apiResponse.read())
            #reportThread = threading.Thread(target=reportGen.reportGen().deviceDetailsReport,args=(details,))
            #reportThread.start()
            return details["result"]["company"], details["result"]["address"]
        except Exception as e:
            log.warning("OUI lookup via API failed: %s", e)
            return "Unknown", "Unknown"

    def oui_identification_via_ieee(self, mac: str) -> tuple[str, str]:
        try:
            mac_obj = EUI(mac)
            mac_oui = mac_obj.oui
            return mac_oui.registration().org, mac_oui.registration().address
        except Exception as e:
            log.warning("OUI lookup via IEEE failed: %s", e)
            return "Unknown", "Unknown"

