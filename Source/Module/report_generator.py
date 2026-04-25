# Report Generation
import os, json, logging
import memory

__all__ = ["ReportGenerator"]

log = logging.getLogger(__name__)


class _ModelEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        return super().default(obj)


def _dumps(obj, **kwargs) -> str:
    return json.dumps(obj, cls=_ModelEncoder, **kwargs)


class ReportGenerator:

    def __init__(self, path: str, filename: str) -> None:
        self.directory = os.path.join(path, "Report")
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        self.filename = filename

    def communicationDetailsReport(self) -> None:
        try:
            comm_file = os.path.join(self.directory, self.filename + "_communication_details.txt")
            with open(comm_file, "w") as f:
                f.write("CommunicationDetails: %s\n" % _dumps(memory.destination_hosts, indent=2, sort_keys=True))
                f.write("Tor Traffic: %s\n" % _dumps(memory.possible_tor_traffic, indent=2, sort_keys=True))
                f.write("Malicious Traffic: %s\n" % _dumps(memory.possible_mal_traffic, indent=2, sort_keys=True))
                f.write("Destination DNS: %s\n" % _dumps(memory.destination_hosts, indent=2, sort_keys=True))
                f.write("Lan Hosts: %s\n" % _dumps(memory.lan_hosts, indent=2, sort_keys=True))
                f.write("Tor Nodes: %s\n" % _dumps(memory.tor_nodes, indent=2, sort_keys=True))
        except Exception as e:
            log.error("Could not create communication details report: %s", e)

    def deviceDetailsReport(self) -> None:
        try:
            device_file = os.path.join(self.directory, self.filename + "_device_details.txt")
            with open(device_file, "w") as f:
                f.write("deviceDetails: %s\n" % _dumps(memory.lan_hosts, indent=2, sort_keys=True))
        except Exception as e:
            log.error("Could not create device details report: %s", e)

    def packetDetails(self) -> None:
        try:
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            with open(packet_file, "w") as f:
                f.write("%s\n" % _dumps(memory.packet_db, indent=2, sort_keys=True))
        except Exception as e:
            log.error("Could not create packet details report, trying backup: %s", e)
            self.backupReport()

    def backupReport(self) -> None:
        try:
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            with open(packet_file, "w") as f:
                for session in memory.packet_db:
                    s = memory.packet_db[session]
                    f.write("\nSession: %s\n" % session)
                    f.write("\nEthernet: %s\n" % s.Ethernet)
                    f.write("\nPayload:\n")
                    fpayloads = "\n".join(s.Payload["forward"])
                    f.write("\nForward:\n")
                    if fpayloads:
                        f.write("%s\n" % fpayloads)
                    rpayloads = "\n".join(s.Payload["reverse"])
                    f.write("\nReverse:\n")
                    if rpayloads:
                        f.write("%s\n" % rpayloads)
                    f.write("=" * 80 + "\n")
        except Exception as e:
            log.error("Could not create packet details report via backup: %s", e)
