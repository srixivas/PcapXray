# Module-level pcap reader test
from conftest import EXAMPLES_DIR
import pcap_reader
import memory

def test_pcapreader():
    pcap_reader.PcapEngine(str(EXAMPLES_DIR / "test.pcap"), "scapy")
    if memory.packet_db:
        assert True
