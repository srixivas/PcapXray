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
        pcap_reader._run_deferred_covert(engine_obj._dns_candidates)

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
        pcap_reader._run_deferred_covert(engine_obj._dns_candidates)

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
        pcap_reader._run_deferred_covert(engine_obj._dns_candidates)

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
        pcap_reader._run_deferred_covert(engine_obj._dns_candidates)
    mock_dns.assert_not_called()


# ── _process_packet (module-level) ───────────────────────────────────────────

def test_process_packet_tcp_private_source():
    """TCP packet from private src to public dst creates a session and LAN host."""
    pkt = NormalizedPacket(
        ip_version=4, src_ip="192.168.1.10", dst_ip="8.8.8.8",
        src_mac="aa:bb:cc:dd:ee:ff", dst_mac="11:22:33:44:55:66",
        proto="TCP", src_port=12345, dst_port=443,
    )
    candidates: dict = {}
    pcap_reader._process_packet(pkt, candidates)
    assert "192.168.1.10/8.8.8.8/443" in memory.packet_db
    assert "aa:bb:cc:dd:ee:ff" in memory.lan_hosts
    assert memory.lan_hosts["aa:bb:cc:dd:ee:ff"].ip == "192.168.1.10"
    assert "8.8.8.8" in memory.destination_hosts


def test_process_packet_udp_dns_queues_candidate():
    """UDP DNS packet queues the qname in candidates for deferred resolution."""
    pkt = NormalizedPacket(
        ip_version=4, src_ip="192.168.1.5", dst_ip="8.8.8.8",
        proto="UDP", src_port=54321, dst_port=53,
        dns_qname="example.com",
    )
    candidates: dict = {}
    pcap_reader._process_packet(pkt, candidates)
    assert any("example.com" == v for v in candidates.values())


def test_process_packet_icmp_tunneled_marks_covert():
    """ICMP packet flagged as tunneled is marked covert immediately."""
    pkt = NormalizedPacket(
        ip_version=4, src_ip="192.168.1.1", dst_ip="1.2.3.4",
        proto="ICMP", icmp_tunneled=True,
    )
    candidates: dict = {}
    pcap_reader._process_packet(pkt, candidates)
    keys = list(memory.packet_db.keys())
    assert keys, "Expected at least one session"
    assert memory.packet_db[keys[0]].covert is True


def test_process_packet_unknown_proto_skipped():
    """Packets with no recognised protocol produce no session."""
    pkt = NormalizedPacket(ip_version=4, src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="")
    pcap_reader._process_packet(pkt, {})
    assert len(memory.packet_db) == 0


# ── LivePcapEngine ────────────────────────────────────────────────────────────

def test_live_pcap_engine_init_resets_memory():
    """Initialising LivePcapEngine clears all memory containers."""
    memory.packet_db["stale"] = PacketSession()
    memory.lan_hosts["ff:ff:ff:ff:ff:ff"] = LanHost(ip="1.2.3.4")
    pcap_reader.LivePcapEngine("lo")
    assert memory.packet_db == {}
    assert memory.lan_hosts == {}


def test_live_pcap_engine_packet_count():
    """_on_packet increments packet_count for each normalised packet."""
    engine = pcap_reader.LivePcapEngine("lo")

    fake_pkt = NormalizedPacket(
        ip_version=4, src_ip="192.168.0.1", dst_ip="8.8.8.8",
        proto="TCP", src_port=1234, dst_port=80,
    )
    with patch("engines.scapy_engine._normalize", return_value=fake_pkt):
        engine._on_packet(object())
        engine._on_packet(object())

    assert engine.packet_count == 2
    assert len(memory.packet_db) >= 1


def test_live_pcap_engine_on_packet_skips_none():
    """_on_packet is a no-op when _normalize returns None."""
    engine = pcap_reader.LivePcapEngine("lo")
    with patch("engines.scapy_engine._normalize", return_value=None):
        engine._on_packet(object())
    assert engine.packet_count == 0
    assert memory.packet_db == {}


def test_live_pcap_engine_on_packet_skips_normalize_exception():
    """_on_packet is a no-op when _normalize raises."""
    engine = pcap_reader.LivePcapEngine("lo")
    with patch("engines.scapy_engine._normalize", side_effect=Exception("bad")):
        engine._on_packet(object())
    assert engine.packet_count == 0


def test_live_pcap_engine_is_running_false_before_start():
    engine = pcap_reader.LivePcapEngine("lo")
    assert engine.is_running() is False


def test_live_pcap_engine_stop_without_start_is_safe():
    """stop() with no sniffer should not raise."""
    engine = pcap_reader.LivePcapEngine("lo")
    with patch("communication_details_fetch.TrafficDetailsFetch.dns"):
        engine.stop()  # must not raise
