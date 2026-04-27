"""Tests for the pluggable engine architecture."""
import importlib
import sys
from unittest.mock import patch, MagicMock

import pytest

import memory
from memory import PacketSession, LanHost, DestinationHost
import pcap_reader
from engines import NormalizedPacket, select_engine
from engines.scapy_engine import ScapyEngine

try:
    from conftest import EXAMPLES_DIR
except ImportError:
    from pathlib import Path
    EXAMPLES_DIR = Path(__file__).parent.parent / "Source" / "Module" / "examples"

TEST_PCAP = str(EXAMPLES_DIR / "test.pcap")


@pytest.fixture(autouse=True)
def reset_memory():
    memory.packet_db = {}
    memory.lan_hosts = {}
    memory.destination_hosts = {}
    memory.possible_tor_traffic = []
    memory.possible_mal_traffic = []
    yield
    memory.packet_db = {}
    memory.lan_hosts = {}
    memory.destination_hosts = {}
    memory.possible_tor_traffic = []
    memory.possible_mal_traffic = []


# ── NormalizedPacket ──────────────────────────────────────────────────────────

def test_normalized_packet_defaults():
    pkt = NormalizedPacket(ip_version=4, src_ip="1.2.3.4", dst_ip="5.6.7.8")
    assert pkt.proto == ""
    assert pkt.src_mac == ""
    assert pkt.payload_bytes == b""
    assert pkt.tls_records == []
    assert pkt.dns_qname == ""
    assert pkt.icmp_tunneled is False


# ── ScapyEngine ───────────────────────────────────────────────────────────────

def test_scapy_engine_yields_normalized_packets():
    engine = ScapyEngine(TEST_PCAP)
    packets = list(engine.stream())
    assert len(packets) > 0
    for pkt in packets:
        assert isinstance(pkt, NormalizedPacket)
        assert pkt.ip_version in (4, 6)
        assert pkt.src_ip
        assert pkt.dst_ip


def test_scapy_engine_produces_sessions():
    pcap_reader.PcapEngine(TEST_PCAP, "scapy")
    assert len(memory.packet_db) > 0


def test_scapy_engine_session_keys_are_triplets():
    pcap_reader.PcapEngine(TEST_PCAP, "scapy")
    for key in memory.packet_db:
        parts = key.split("/")
        assert len(parts) == 3, f"Bad key format: {key!r}"


# ── DpktEngine ────────────────────────────────────────────────────────────────

try:
    import dpkt as _dpkt_probe
    _dpkt_present = True
except ImportError:
    _dpkt_present = False

skipif_no_dpkt = pytest.mark.skipif(not _dpkt_present, reason="dpkt not installed")


@skipif_no_dpkt
def test_dpkt_engine_yields_normalized_packets():
    from engines.dpkt_engine import DpktEngine
    engine = DpktEngine(TEST_PCAP)
    packets = list(engine.stream())
    assert len(packets) > 0
    for pkt in packets:
        assert isinstance(pkt, NormalizedPacket)


@skipif_no_dpkt
def test_dpkt_engine_session_count_matches_scapy():
    from engines.dpkt_engine import DpktEngine
    pcap_reader.PcapEngine(TEST_PCAP, "dpkt")
    dpkt_count = len(memory.packet_db)

    memory.packet_db = {}
    pcap_reader.PcapEngine(TEST_PCAP, "scapy")
    scapy_count = len(memory.packet_db)

    # Counts may differ slightly due to different protocol parsing depth,
    # but should be in the same ballpark (within 20%).
    assert abs(dpkt_count - scapy_count) <= max(scapy_count * 0.2, 2), (
        f"dpkt={dpkt_count} vs scapy={scapy_count} — too far apart"
    )


# ── select_engine fallback ────────────────────────────────────────────────────

def test_select_engine_auto_falls_back_to_scapy_when_dpkt_absent():
    # Patch dpkt_engine to simulate missing dpkt
    with patch("engines.dpkt_engine._dpkt_available", False):
        engine = select_engine("auto", TEST_PCAP)
    assert isinstance(engine, ScapyEngine)


def test_select_engine_unknown_name_raises():
    with pytest.raises(ValueError, match="Unknown engine"):
        select_engine("nonexistent", TEST_PCAP)


def test_select_engine_scapy_explicit():
    engine = select_engine("scapy", TEST_PCAP)
    assert isinstance(engine, ScapyEngine)


# ── Deferred covert detection ─────────────────────────────────────────────────

def test_deferred_covert_marks_session():
    """DNS sessions with unresolvable qnames are marked covert post-loop."""
    # Seed a DNS session manually so it lands in _dns_candidates
    memory.packet_db["10.0.0.1/8.8.8.8/53"] = PacketSession()
    memory.lan_hosts["aa:bb:cc:dd:ee:ff"] = LanHost(ip="10.0.0.1")
    memory.destination_hosts["8.8.8.8"] = DestinationHost(mac="11:22:33:44:55:66")

    engine_obj = pcap_reader.PcapEngine.__new__(pcap_reader.PcapEngine)
    engine_obj.engine = "scapy"
    engine_obj._dns_candidates = {
        "10.0.0.1/8.8.8.8/53": "xn--nxasmq6b3b4d3d.test"
    }

    with patch(
        "communication_details_fetch.TrafficDetailsFetch.dns",
        return_value="NotResolvable",
    ):
        engine_obj._run_deferred_covert()

    assert memory.packet_db["10.0.0.1/8.8.8.8/53"].covert is True


def test_deferred_covert_does_not_mark_resolvable():
    memory.packet_db["10.0.0.1/8.8.8.8/53"] = PacketSession()

    engine_obj = pcap_reader.PcapEngine.__new__(pcap_reader.PcapEngine)
    engine_obj.engine = "scapy"
    engine_obj._dns_candidates = {"10.0.0.1/8.8.8.8/53": "example.com"}

    with patch(
        "communication_details_fetch.TrafficDetailsFetch.dns",
        return_value="example.com",
    ):
        engine_obj._run_deferred_covert()

    assert memory.packet_db["10.0.0.1/8.8.8.8/53"].covert is False


def test_deferred_covert_deduplicates_qnames():
    """Same qname used by two sessions should only trigger one DNS call."""
    memory.packet_db["10.0.0.1/8.8.8.8/53"] = PacketSession()
    memory.packet_db["10.0.0.2/8.8.8.8/53"] = PacketSession()

    engine_obj = pcap_reader.PcapEngine.__new__(pcap_reader.PcapEngine)
    engine_obj.engine = "scapy"
    engine_obj._dns_candidates = {
        "10.0.0.1/8.8.8.8/53": "same.qname.test",
        "10.0.0.2/8.8.8.8/53": "same.qname.test",
    }

    call_count = []

    def fake_dns(qname):
        call_count.append(qname)
        return "NotResolvable"

    with patch("communication_details_fetch.TrafficDetailsFetch.dns", side_effect=fake_dns):
        engine_obj._run_deferred_covert()

    assert len(call_count) == 1, "Expected exactly one DNS call for duplicate qnames"
    assert memory.packet_db["10.0.0.1/8.8.8.8/53"].covert is True
    assert memory.packet_db["10.0.0.2/8.8.8.8/53"].covert is True


def test_deferred_covert_no_op_when_empty():
    engine_obj = pcap_reader.PcapEngine.__new__(pcap_reader.PcapEngine)
    engine_obj.engine = "scapy"
    engine_obj._dns_candidates = {}
    with patch(
        "communication_details_fetch.TrafficDetailsFetch.dns"
    ) as mock_dns:
        engine_obj._run_deferred_covert()
    mock_dns.assert_not_called()
