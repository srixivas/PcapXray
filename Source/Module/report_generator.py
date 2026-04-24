# Report Generation
import os, json
import memory

class reportGen:

    def __init__(self, path: str, filename: str) -> None:
        self.directory = os.path.join(path, "Report")
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        self.filename = filename

    def communicationDetailsReport(self) -> None:
        try:
            comm_file = os.path.join(self.directory, self.filename + "_communication_details.txt")
            text_handle = open(comm_file, "w")
            text_handle.write("CommunicationDetails: %s\n" % json.dumps(memory.destination_hosts, indent=2,sort_keys=True))
            text_handle.write("Tor Traffic: %s\n" % json.dumps(memory.possible_tor_traffic, indent=2,sort_keys=True))
            text_handle.write("Malicious Traffic: %s\n" % json.dumps(memory.possible_mal_traffic, indent=2,sort_keys=True))
            text_handle.write("Destination DNS: %s\n" % json.dumps(memory.destination_hosts, indent=2,sort_keys=True))
            text_handle.write("Lan Hosts: %s\n" % json.dumps(memory.lan_hosts, indent=2,sort_keys=True))
            text_handle.write("Tor Nodes: %s\n" % json.dumps(memory.tor_nodes, indent=2,sort_keys=True))
            text_handle.close()
        except Exception as e:
            print("Could not create the report text file !!!!! Please debug error %s" % (str(e)))

    def deviceDetailsReport(self) -> None:
        try:
            device_file = os.path.join(self.directory, self.filename + "_device_details.txt")
            text_handle = open(device_file, "w")
            text_handle.write("deviceDetails: %s\n" % json.dumps(memory.lan_hosts, indent=2,sort_keys=True))
            text_handle.close()
        except Exception as e:
            print("Could not create the report text file !!!!! Please debug error %s" % (str(e)))

    def packetDetails(self) -> None:
        try:
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            text_handle = open(packet_file, "w")
            text_handle.write("%s\n" % json.dumps(memory.packet_db, indent=2, sort_keys=True))            
            text_handle.close()
        except Exception as e:
            print("Could not create the report text file, trying backup mode !!!!! %s" % (str(e)))
            self.backupReport()

    def backupReport(self) -> None:
        try:
            packet_file = os.path.join(self.directory, self.filename + "_packet_details.txt")
            text_handle = open(packet_file, "w")
            # <TODO>: Do we need to format payload?
            for session in memory.packet_db:
                text_handle.write("\nSession: %s\n" % session)
                text_handle.write("\nEthernet: %s\n" % memory.packet_db[session]["Ethernet"])
                text_handle.write("\nPayload:\n")
                fpayloads = "\n".join(memory.packet_db[session]["Payload"]["forward"])
                text_handle.write("\nForward:\n")
                if fpayloads:
                    text_handle.write("%s\n" % fpayloads)
                rpayloads = "\n".join(memory.packet_db[session]["Payload"]["reverse"])
                text_handle.write("\nReverse:\n")
                if rpayloads:
                    text_handle.write("%s\n" % rpayloads)                
                text_handle.write("="*80+"\n")
            text_handle.close()
        except Exception as e:
            print("Could not create the report text file by backup method !!!!! Please debug error %s" % (str(e)))