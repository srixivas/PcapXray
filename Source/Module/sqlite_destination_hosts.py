import sqlite3
from collections import abc
import json
import os
import malicious_traffic_identifier
import communication_details_fetch

# https://stackoverflow.com/questions/2390827/how-to-properly-subclass-dict-and-override-getitem-setitem
class DictInstance(dict):
    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __getitem__(self, key):
        val = super().__getitem__(key)
        return val

    def __setitem__(self, key, val):
        if key not in ["host_ip", "domain_name", "mac"]:
            raise AttributeError("Only attributes valid for a destination host are : 'host_ip', 'domain_name', 'mac'")
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
class SqliteDestinationHosts:
    def __init__(self):
        self.instance_dict = {}

    def create_table(self, directory, filename, con, cur):
        self.directory = directory
        self.filename = filename
        self.con = con
        self.cur = cur
        
        # Create packet table if it doesn't exist yet
        create_table_string = """CREATE TABLE IF NOT EXISTS destination_hosts (
            host_ip STRING NOT NULL,
            domain_name STRING,
            mac STRING
        ); """
        self.cur.execute(create_table_string)
                
        # Commit changes
        self.con.commit()

    # creates an instance of the destination host
    def create_instance(self, host_ip):
        # Making a temp destination host
        self.instance = DictInstance()
        self.instance["host_ip"] = host_ip
        self.instance["domain_name"] = ""
        self.instance["mac"] = ""
        
    # the current instance is saved to the db
    def save_instance(self):
        self.instance_dict[self.instance["host_ip"]] = self.instance
        self.instance = None
    
    # commits all saved instances to the database
    def commit(self):
        self.cur.executemany("""
            INSERT INTO destination_hosts(host_ip, domain_name, mac)
            VALUES(:host_ip, :domain_name, :mac)
            """, 
            self.iterator_for_database_dumping()
        )
        self.con.commit()
    
    # yields as json dumped the list of packets saved by save_packet
    def iterator_for_database_dumping(self):
        for packet in self.packets_dict.values():
            yield { 
                "host_ip": instance["host_ip"],
                "domain_name": self.data_to_json(instance["domain_name"]),
                "mac": self.data_to_json(instance["mac"]),
            }

    # gets an instance from a given host_ip
    def __getitem__(self, host_ip):
        if host_ip != self.host_ip:
            self.host_ip = host_ip
            self.cur.execute("SELECT host_ip, domain_name, mac FROM destination_hosts WHERE host_ip = ?", [host_ip])
            self.instance = DictInstance()
            row = self.cur.fetchone()
            if row :
                self.packet = self.row_to_instance(row)
            else :
                return None
            self.host_ip = host_ip
            self.instance["host_ip"] = host_ip
        return self.instance

    # returns all packets in the database
    def get_all(self):
        self.cur.execute("SELECT host_ip, domain_name, mac FROM destination_hosts")
        instancess = []
        for row in self.cur.fetchall():
            instance = self.row_to_instance(row)
            instances.append(instance)
        return packets

    # takes a row and returns a packet from it
    def row_to_instance(self, row):
        instance = DictInstance()
        instance["host_ip"] = json.loads(row[0])
        instance["domain_name"] = json.loads(row[1])
        instance["mac"] = json.loads(row[2])
           
        return packet

    # returns the list of all session keys in the database
    def keys(self):
        self.cur.execute("SELECT host_ip FROM destination_hosts")
        keys = []
        for row in self.cur.fetchall():
            keys.append(row[0])
        return keys

    def data_to_json(self, data):
        return json.dumps(data)

