#File Import
#import pcap_reader
import communication_details_fetch
import tor_traffic_handle
import malicious_traffic_identifier
#import device_details_fetch
import memory
import logging

import networkx as nx
#import matplotlib.pyplot as plt

from graphviz import Digraph
import threading
import os

from pyvis.network import Network

log = logging.getLogger(__name__)

def _node_label(mac: str) -> str:
    h = memory.lan_hosts[mac]
    if h.node:
        return h.node
    return h.ip.replace(":", ".") + "\n" + mac.replace(":", ".")

class plotLan:

    def __init__(self, filename, path, option="Tor", to_ip="All", from_ip="All"):
        log.info("plotLan init: option=%s to=%s from=%s", option, to_ip, from_ip)
        self.directory = os.path.join(path, "Report")
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        options = option + "_" + to_ip.replace(".", "-") + "_" + from_ip.replace(".", "-")
        self.filename = os.path.join(self.directory, filename+"_"+options)

        self.styles = {
            'graph': {
                'label': 'PcapGraph',
                'fontsize': '16',
                'fontcolor': 'black',
                'bgcolor': 'grey',
                'rankdir': 'LR', # BT
                'dpi':'300',
                'size': '10, 10',
                'overlap': 'scale'
            },
            'nodes': {
                'fontname': 'Helvetica',
                'shape': 'circle',
                'fontcolor': 'black',
                'color': ' black',
                'style': 'filled',
                'fillcolor': 'yellow',
                'fixedsize': 'true',
                'width': '3',
                'height': '3'
            }
        }

        self.sessions = list(memory.packet_db.keys())
        log.info("plotLan: %d sessions in packet_db", len(self.sessions))
        #device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
        if option == "Malicious" or option == "All":
            log.info("Running malicious traffic identification")
            self.mal_identify = malicious_traffic_identifier.maliciousTrafficIdentifier()
            log.info("Malicious traffic identification done")
        if option == "Tor" or option == "All":
            log.info("Running Tor traffic detection")
            self.tor_identify = tor_traffic_handle.torTrafficHandle().tor_traffic_detection()
            log.info("Tor traffic detection done")
        log.info("Calling draw_graph")
        self.draw_graph(option, to_ip, from_ip)
        log.info("draw_graph complete")
    
    def apply_styles(self, graph, styles):
        graph.graph_attr.update(
            ('graph' in styles and styles['graph']) or {}
        )
        graph.node_attr.update(
            ('nodes' in styles and styles['nodes']) or {}
        )
        return graph

    def apply_custom_style(self, graph, color):
        style = {'edges': {
                'style': 'dashed',
                'color': color,
                'arrowhead': 'open',
                'fontname': 'Courier',
                'fontsize': '12',
                'fontcolor': color,
        }}
        graph.edge_attr.update(
            ('edges' in style and style['edges']) or {}
        )
        return graph

    def draw_graph(self, option="All", to_ip="All", from_ip="All"):
        #f = Digraph('network_diagram - '+option, filename=self.filename, engine="dot", format="png")
        #f.attr(rankdir='LR', size='8,5')
        if len(memory.lan_hosts) > 40:
            f = Digraph('network_diagram - '+option, filename=self.filename, engine="sfdp", format="png")
        elif len(memory.lan_hosts) > 20:
            f = Digraph('network_diagram - '+option, filename=self.filename, engine="circo", format="png")
        else:
            f = Digraph('network_diagram - '+option, filename=self.filename, engine="dot", format="png")
        
        interactive_graph = Network(directed=True, height="750px", width="100%", bgcolor="#222222", font_color="white")
        interactive_graph.barnes_hut()
        vis_nodes = []
        vis_edges = []

        f.attr('node', shape='doublecircle')
        #f.node('defaultGateway')

        f.attr('node', shape='circle')

        log.info("draw_graph: option=%s sessions=%d", option, len(self.sessions))
        edge_present = False

        mal, tor, http, https, icmp, dns, clear_text, unknown, covert = 0, 0, 0, 0, 0, 0, 0, 0, 0

        if option == "All":
            # add nodes
            for session in self.sessions:
                src, dst, port = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst
                    
                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    #if (curr_node, curr_node, title=curr_node, color="yellow") not in vis_nodes:
                    #    vis_nodes.append((curr_node, curr_node, title=curr_node, color="yellow"))
                    #if (destination, destination, title=destination, color="yellow") not in vis_nodes:
                    #    vis_nodes.append((destination, destination, title=destination, color="yellow"))

                    if curr_node != destination:
                        if session in memory.possible_tor_traffic:
                            f.edge(curr_node, destination, label='TOR: ' + str(map_dst) ,color="white")
                            tor += 1
                            #interactive_graph.add_edge(curr_node, destination, color="white", value=tor/100, smooth={type: "curvedCCW", roundness: 0.4})
                            interactive_graph.add_edge(curr_node, destination, color="white", title='TOR: ' + str(map_dst), smooth={"type": "curvedCW", "roundness": tor/9})
                            #if edge not in vis_edges:toor
                            #    vis_edges.append(edge)
                            if edge_present == False:
                                edge_present = True
                        elif memory.packet_db[session].covert:
                            if port == "53":
                                protocol = "DNS"
                            else:
                                protocol = port
                            f.edge(curr_node, destination, label='Covert/'+ protocol + ': ' + str(map_dst) +": "+str(dlabel), color = "cyan")
                            covert += 1
                            interactive_graph.add_edge(curr_node, destination, color="cyan", title='Covert: ' + str(map_dst) +": "+dlabel, smooth={"type": "curvedCCW", "roundness": covert/12})
                            if edge_present == False:
                                edge_present = True
                        else:
                            if port == "443":
                                f.edge(curr_node, destination, label='HTTPS: ' + str(map_dst) +": "+str(dlabel), color = "blue")
                                https += 1
                                interactive_graph.add_edge(curr_node, destination, color="blue", title='HTTPS: ' + str(map_dst) +": "+dlabel, smooth={"type": "curvedCCW", "roundness": https/10})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "80":
                                f.edge(curr_node, destination, label='HTTP: ' + str(map_dst) +": "+str(dlabel), color = "green")
                                http += 1
                                interactive_graph.add_edge(curr_node, destination, color="green", title='HTTP: ' + str(map_dst) +": "+dlabel, smooth={"type": "curvedCW", "roundness": http/12})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "ICMP":
                                f.edge(curr_node, destination, label='ICMP: ' + str(map_dst) ,color="black")
                                icmp += 1
                                interactive_graph.add_edge(curr_node, destination, color="purple", title='ICMP: ' + str(map_dst), smooth={"type": "curvedCCW", "roundness": icmp/6})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "53":
                                f.edge(curr_node, destination, label='DNS: ' + str(map_dst) ,color="orange")
                                dns += 1
                                interactive_graph.add_edge(curr_node, destination, color="pink", title='DNS: ' + str(map_dst), smooth={"type": "curvedCW", "roundness": dns/5})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif int(port) in [20, 21, 23, 25, 110, 143, 139, 69, 161, 162, 1521]:
                                f.edge(curr_node, destination, label='ClearTextProtocol/'+ port +': ' +  str(map_dst) ,color="violet")
                                clear_text += 1
                                interactive_graph.add_edge(curr_node, destination, color="#9A2EFE", title='ClearTextProtocol/'+ port +': ' + str(map_dst), smooth={"type": "curvedCW", "roundness": clear_text/4})
                                if edge_present == False:
                                    edge_present = True
                            else:
                                f.edge(curr_node, destination, label='UnknownProtocol/'+ port +': ' + str(map_dst) ,color="brown")
                                unknown += 1
                                interactive_graph.add_edge(curr_node, destination, color="brown", title='UnknownProtocol/' + port + ': ' + str(map_dst), smooth={"type": "curvedCW", "roundness": unknown/3})
                                if edge_present == False:
                                    edge_present = True
                    else:
                        # This block was just added to handle MAC SPOOF scenario
                        # * Most of the CTF Challenges have fake identical MACs that need to be displayed
                        if map_src in curr_node:
                            other_node = map_dst + "\n" + memory.packet_db[session].Ethernet["dst"].replace(":",".")
                        else:
                            other_node = map_src + "\n" + memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(other_node)
                        interactive_graph.add_node(str(other_node), str(other_node), title=str(other_node), color="yellow")
                        f.edge(curr_node, other_node, label='WeirdTraffic/'+ port ,color="pink")
                        unknown += 1
                        interactive_graph.add_edge(curr_node, other_node, color="pink", title='WeirdTraffic/' + port, smooth={"type": "curvedCW", "roundness": unknown/3})
                        if edge_present == False:
                            edge_present = True    

        elif option == "HTTP":
            for session in self.sessions:
                src, dst, port = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if port == "80" and curr_node != destination:
                        f.edge(curr_node, destination, label='HTTP: ' + str(map_dst)+": "+dlabel, color = "green")
                        http += 1
                        interactive_graph.add_edge(curr_node, destination, color="green", smooth={"type": "curvedCW", "roundness": http/10})
                        if edge_present == False:
                            edge_present = True

        elif option == "HTTPS":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if port == "443" and curr_node != destination:
                        f.edge(curr_node, destination, label='HTTPS: ' + str(map_dst)+": "+dlabel, color = "blue")
                        https += 1
                        interactive_graph.add_edge(curr_node, destination, color="blue", smooth={"type": "curvedCCW", "roundness": https/10})
                        if edge_present == False:
                            edge_present = True

        elif option == "Tor":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if session in memory.possible_tor_traffic and curr_node != destination:
                        f.edge(curr_node, destination, label='TOR: ' + str(map_dst) ,color="white")
                        tor += 1
                        interactive_graph.add_edge(curr_node, destination, color="white", smooth={"type": "curvedCW", "roundness": tor/10})
                        if edge_present == False:
                            edge_present = True

        elif option == "Malicious":
            # TODO: would we need to iterate over and over all the session irrespective of the properties
            for session in self.sessions:
                src, dst, port = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if session in memory.possible_mal_traffic and curr_node != destination:
                        f.edge(curr_node, destination, label='Malicious: ' + str(map_dst) ,color="red")
                        mal += 1
                        interactive_graph.add_edge(curr_node, destination, color="red", smooth={"type": "curvedCW", "roundness": mal/10})                 
                        if edge_present == False:
                            edge_present = True
            
        elif option == "ICMP":
            for session in self.sessions:
                src, dst, protocol = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if protocol == "ICMP" and curr_node != destination:
                        f.edge(curr_node, destination, label='ICMP: ' + str(map_dst) ,color="black")
                        icmp += 1
                        interactive_graph.add_edge(curr_node, destination, color="purple", smooth={"type": "curvedCCW", "roundness": icmp/10})        
                        if edge_present == False:
                            edge_present = True
    
        elif option == "DNS":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session].Ethernet["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session].Ethernet["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = _node_label(memory.packet_db[session].Ethernet["src"])
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst].mac in memory.lan_hosts:
                            destination = _node_label(memory.destination_hosts[dst].mac)
                            dlabel = memory.destination_hosts[dst].domain_name
                        else:
                            destination = memory.destination_hosts[dst].mac.replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst].domain_name
                    else:
                        if memory.packet_db[session].Ethernet["dst"] in memory.lan_hosts:
                            destination = _node_label(memory.packet_db[session].Ethernet["dst"])
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session].Ethernet["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination), color="yellow")
                    except Exception as e:
                        log.warning("Interactive graph node error: %s", e)

                    if port == "53" and curr_node != destination:
                        f.edge(curr_node, destination, label='DNS: ' + str(map_dst) ,color="orange")
                        dns += 1
                        interactive_graph.add_edge(curr_node, destination, color="pink", smooth={"type": "curvedCW", "roundness": dns/10})        
                        if edge_present == False:
                            edge_present = True

        if not edge_present:
            # Discard all the bloated disconnected nodes — lay out a trivial graph instead.
            f = Digraph("no_traffic", filename=self.filename, engine="dot", format="png")
            f.attr(label="No " + option + " Traffic between nodes!", fontsize="20",
                   bgcolor="grey", size="5,5", dpi="300")

        self.apply_styles(f, self.styles)

        log.info("Rendering graphviz PNG: %s", self.filename)
        try:
            f.render(timeout=30)
        except TypeError:
            f.render()
        log.info("Graphviz render complete")

        log.info("Saving interactive HTML: %s.html", self.filename)
        interactive_graph.show_buttons(filter_=['physics'])
        interactive_graph.save_graph(self.filename + ".html")
        log.info("Interactive HTML saved")
                
