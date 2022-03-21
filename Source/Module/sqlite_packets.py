import sqlite3
from collections import abc
import json
import os
import malicious_traffic_identifier
import communication_details_fetch

# https://stackoverflow.com/questions/2390827/how-to-properly-subclass-dict-and-override-getitem-setitem
class DictPacket(dict):
    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __getitem__(self, key):
        val = super().__getitem__(key)
        return val

    def __setitem__(self, key, val):
        if key not in ["session_key", "Ethernet", "Payload", "covert", "file_signatures"]:
            raise AttributeError("Only attributes valid for a packet are : 'session_key', 'Ethernet', 'Payload', 'covert', 'file_signatures'")
        super().__setitem__(key, val)

    def __repr__(self):
        dictrepr = super().__repr__()
        return '%s(%s)' % (type(self).__name__, dictrepr)
        
    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).items():
            self[k] = v
#
# 
#
class SqlitePackets:
    def __init__(self):
        # Session key for packets
        self.session_key = ""
        
        # All packets saved before commit
        # commit cleans this dict
        self.packets_dict = {}    

    def create_table(self, directory, filename, con, cur):
        self.directory = directory
        self.filename = filename
        self.con = con
        self.cur = cur
        
        # Create packet table if it doesn't exist yet
        create_table_string = """CREATE TABLE IF NOT EXISTS packets (
            session_key STRING NOT NULL,
            Ethernet STRING,
            Payload STRING,
            covert STRING,
            file_signatures STRING
        ); """
        self.cur.execute(create_table_string)
                
        # Commit changes
        self.con.commit()

    # creates a packet as an intance variable
    def create_packet(self, session_key):
        # Making a temp packet
        self.packet = DictPacket()
        # Session key
        self.packet["session_key"] = session_key
        # MAC
        self.packet["Ethernet"] = {"src":"", "dst":""}
        # Record Payloads 
        # Record unidirectional + bidirectional separate
        self.packet["Payload"] = {"forward":[],"reverse":[]}
        # Covert Communication Identifier
        self.packet["covert"] = False
        # File Signature Identifier
        self.packet["file_signatures"] = []

        src, dst, port = session_key.split("/")
        # Covert detection and store
        if "covert" in self.packet and self.packet["covert"] == False and \
            not communication_details_fetch.trafficDetailsFetch.is_multicast(src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst) and \
                malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(self.packet) == 1:
                    self.packet["covert"] = True

    # the packet in the instance is stored to a dict
    def save_packet(self):
        self.packets_dict[self.packet["session_key"]] = self.packet
        self.packet = None
    
    # commits all saved packets to the database
    def commit(self):
        self.cur.executemany("""
            INSERT INTO packets(session_key, Ethernet, Payload, covert, file_signatures)
            VALUES(:session_key, :Ethernet, :Payload, :covert, :file_signatures)
            """, 
            self.iterator_for_database_dumping()
        )
        self.con.commit()
    
    # yields as json dumped the list of packets saved by save_packet
    def iterator_for_database_dumping(self):
        print("!! DUMPING !!")
        for packet in self.packets_dict.values():
            if packet["session_key"] == "2607:f8b0:400d:c0a::63/2604:2000:71d6:400:3cc2:834:5d8e:c6bd/57924":
                print("-- BAD ONE! --")
            yield { 
                "session_key": packet["session_key"],
                "Ethernet": self.data_to_json(packet["Ethernet"]),
                "Payload": self.data_to_json(packet["Payload"]),
                "covert": self.data_to_json(packet["covert"]),
                "file_signatures": self.data_to_json(packet["file_signatures"])
            }

    
    # gets a packet from a given session_key
    def __getitem__(self, session_key):
        if session_key != self.session_key:
            self.session_key = session_key
            self.cur.execute("SELECT Ethernet, Payload, covert, file_signatures FROM packets WHERE session_key = ?", [session_key])
            self.packet = DictPacket()
            row = self.cur.fetchone()
            if row :
                self.packet = self.row_to_packet(row)
            else :
                return None
            self.session_key = session_key
            self.packet["session_key"] = session_key
        return self.packet

    # returns all packets in the database
    def get_all(self):
        self.cur.execute("SELECT Ethernet, Payload, covert, file_signatures, session_key FROM packets")
        packets = []
        for row in self.cur.fetchall():
            packet = self.row_to_packet(row)
            packets.append(packet)
        return packets

    # takes a row and returns a packet from it
    def row_to_packet (self, row):
        packet = DictPacket()
        packet["Ethernet"] = json.loads(row[0])
        packet["Payload"] = json.loads(row[1])
        packet["covert"] = json.loads(row[2])
        packet["file_signatures"] = json.loads(row[3])
        if row[4] :
            packet["session_key"] = str(row[4])
        return packet

    # returns the list of all session keys in the database
    def session_keys(self):
        self.cur.execute("SELECT session_key FROM packets")
        keys = []
        for row in self.cur.fetchall():
            keys.append(row[0])
        return keys

    def data_to_json(self, data):
        return json.dumps(data)

