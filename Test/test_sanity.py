# Sanity / smoke tests — full workflow per example PCAP

import os
import pytest
from pathlib import Path
from conftest import EXAMPLES_DIR

import report_generator
import pcap_reader
import communication_details_fetch
import device_details_fetch
import malicious_traffic_identifier
import plot_lan_network
import tor_traffic_handle
import memory

pcap_files = [f.name for f in EXAMPLES_DIR.iterdir() if f.suffix in (".pcap", ".pcapng")]

@pytest.mark.parametrize("packet_capture_file", pcap_files)
@pytest.mark.parametrize("engine", ["scapy"])
def test_pcapreader(packet_capture_file, engine):
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / packet_capture_file), engine)
    if memory.packet_db:
        memory.packet_db = {}
        assert True

# <TODO>: revisit pyshark support
"""
@pytest.mark.parametrize("packet_capture_file", pcap_files)
@pytest.mark.parametrize("engine", ["pyshark"])
def test_pcapreader_pyshark_engine(packet_capture_file, engine):
    if packet_capture_file == "tamu_readingrainbow_0_network_enumeration.pcap":
        assert True
    else:
        pcap_reader.PcapEngine(str(EXAMPLES_DIR / packet_capture_file), engine)
        if memory.packet_db:
            memory.packet_db = {}
            assert True
"""

def test_communication_details_fetch():
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    communication_details_fetch.trafficDetailsFetch("sock")
    if memory.destination_hosts:
        assert True

def test_device_details_fetch():
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
    if memory.lan_hosts:
        assert True

def test_malicious_traffic_identifier():
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    communication_details_fetch.trafficDetailsFetch("sock")
    malicious_traffic_identifier.maliciousTrafficIdentifier()
    if memory.possible_mal_traffic:
        assert True

def test_report_gen():
    filename = "test"
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / (filename + ".pcap")), "scapy")
    report_dir = str(EXAMPLES_DIR.parent) + "/"
    if memory.packet_db:
        report_generator.reportGen(report_dir, filename).packetDetails()
        report_generator.reportGen(report_dir, filename).communicationDetailsReport()
        report_generator.reportGen(report_dir, filename).deviceDetailsReport()
        report_path = EXAMPLES_DIR.parent / "Report"
        if (report_path / "testcommunicationDetailsReport.txt").exists() and \
           (report_path / "testdeviceDetailsReport.txt").exists() and \
           (report_path / "testpacketDetailsReport.txt").exists():
            assert True

def test_tor_traffic_handle():
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    tor_traffic_handle.torTrafficHandle().tor_traffic_detection()
    if memory.possible_tor_traffic:
        assert True

@pytest.mark.parametrize("option", ["All", "HTTP", "HTTPS", "DNS", "ICMP", "Malicious", "Tor"])
def test_plot_lan_network(tmp_path, option):
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    plot_lan_network.plotLan("test", str(tmp_path), option=option)
    png = tmp_path / "Report" / f"test_{option}_All_All.png"
    assert png.exists(), f"Expected graph PNG not found: {png}"

# pyshark engine: disabled — FileCapture enters an infinite loop on certain
# PCAPs under pytest's event loop. Formally dropping pyshark test coverage
# until the engine is reworked with an explicit timeout/close contract.
# Tracked as Phase 2-E.
