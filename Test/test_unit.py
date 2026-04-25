# Phase 2-D: focused unit tests per module, external calls mocked

import pytest
import socket
from unittest.mock import patch, MagicMock, mock_open

import memory
from memory import PacketSession, LanHost, DestinationHost
import communication_details_fetch
import device_details_fetch
import malicious_traffic_identifier
import tor_traffic_handle
import report_generator


@pytest.fixture(autouse=True)
def reset_memory():
    memory.packet_db.clear()
    memory.lan_hosts.clear()
    memory.destination_hosts.clear()
    memory.tor_nodes.clear()
    memory.possible_tor_traffic.clear()
    memory.possible_mal_traffic.clear()
    memory.signatures.clear()
    yield


# ─────────────────────────── communication_details_fetch ────────────────────────────

class TestIsMulticast:
    def test_ipv4_multicast_224(self):
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("224.0.0.1") is True

    def test_ipv4_multicast_239(self):
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("239.255.255.255") is True

    def test_ipv4_unicast(self):
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("192.168.1.1") is False

    def test_ipv4_broadcast_treated_as_multicast(self):
        # First octet 255 >= 224, so broadcast is intentionally treated as non-unicast
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("255.255.255.255") is True

    def test_ipv6_multicast(self):
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("FF0e::1") is True

    def test_ipv6_unicast(self):
        assert communication_details_fetch.trafficDetailsFetch.is_multicast("2001:db8::1") is False


class TestDnsStatic:
    def test_resolves_hostname(self):
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   return_value=("example.com", [], ["1.2.3.4"])):
            assert communication_details_fetch.trafficDetailsFetch.dns("1.2.3.4") == "example.com"

    def test_oserror_returns_not_resolvable(self):
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   side_effect=OSError("no route to host")):
            assert communication_details_fetch.trafficDetailsFetch.dns("1.2.3.4") == "NotResolvable"

    def test_restores_socket_timeout_after_success(self):
        original = socket.getdefaulttimeout()
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   return_value=("host.local", [], [])):
            communication_details_fetch.trafficDetailsFetch.dns("10.0.0.1")
        assert socket.getdefaulttimeout() == original

    def test_restores_socket_timeout_after_error(self):
        original = socket.getdefaulttimeout()
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   side_effect=OSError("fail")):
            communication_details_fetch.trafficDetailsFetch.dns("10.0.0.1")
        assert socket.getdefaulttimeout() == original


class TestTrafficDetailsFetch:
    def test_populates_domain_name_on_success(self):
        memory.destination_hosts["1.2.3.4"] = DestinationHost()
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   return_value=("resolved.example.com", [], ["1.2.3.4"])):
            communication_details_fetch.trafficDetailsFetch("sock")
        assert memory.destination_hosts["1.2.3.4"].domain_name == "resolved.example.com"

    def test_marks_failed_lookup_not_resolvable(self):
        memory.destination_hosts["5.6.7.8"] = DestinationHost()
        with patch("communication_details_fetch.socket.gethostbyaddr",
                   side_effect=OSError("NXDOMAIN")):
            communication_details_fetch.trafficDetailsFetch("sock")
        assert memory.destination_hosts["5.6.7.8"].domain_name == "NotResolvable"

    def test_skips_already_resolved_hosts(self):
        memory.destination_hosts["1.2.3.4"] = DestinationHost(domain_name="pre.resolved.com")
        with patch("communication_details_fetch.socket.gethostbyaddr") as mock_dns:
            communication_details_fetch.trafficDetailsFetch("sock")
        mock_dns.assert_not_called()


# ────────────────────────────── device_details_fetch ────────────────────────────────

class TestOuiViaApi:
    def _make_response(self, company="Acme Corp", address="123 Main St"):
        import json
        resp = MagicMock()
        resp.read.return_value = json.dumps(
            {"result": {"company": company, "address": address}}
        ).encode()
        return resp

    def test_returns_company_and_address(self):
        fetcher = device_details_fetch.fetchDeviceDetails("api")
        with patch("device_details_fetch.urllib.request.urlopen",
                   return_value=self._make_response("Apple Inc", "Cupertino")):
            vendor, addr = fetcher.oui_identification_via_api("AA:BB:CC:DD:EE:FF")
        assert vendor == "Apple Inc"
        assert addr == "Cupertino"

    def test_returns_unknown_on_http_error(self):
        fetcher = device_details_fetch.fetchDeviceDetails("api")
        with patch("device_details_fetch.urllib.request.urlopen",
                   side_effect=Exception("HTTP 503")):
            vendor, addr = fetcher.oui_identification_via_api("AA:BB:CC:DD:EE:FF")
        assert vendor == "Unknown"
        assert addr == "Unknown"


class TestOuiViaIeee:
    def test_returns_org_and_address(self):
        fetcher = device_details_fetch.fetchDeviceDetails("ieee")
        reg = MagicMock()
        reg.org = "Intel Corp"
        reg.address = "Santa Clara, CA"
        mock_eui = MagicMock()
        mock_eui.oui.registration.return_value = reg
        with patch("device_details_fetch.EUI", return_value=mock_eui):
            vendor, addr = fetcher.oui_identification_via_ieee("AA:BB:CC:DD:EE:FF")
        assert vendor == "Intel Corp"
        assert addr == "Santa Clara, CA"

    def test_returns_unknown_on_lookup_failure(self):
        fetcher = device_details_fetch.fetchDeviceDetails("ieee")
        with patch("device_details_fetch.EUI", side_effect=Exception("bad MAC")):
            vendor, addr = fetcher.oui_identification_via_ieee("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
        assert vendor == "Unknown"
        assert addr == "Unknown"


class TestFetchInfo:
    def test_sets_node_key_for_ipv4_host(self):
        memory.lan_hosts["AA:BB:CC:DD:EE:FF"] = LanHost(ip="192.168.1.10")
        with patch("device_details_fetch.EUI") as mock_eui_cls:
            reg = MagicMock()
            reg.org = "VendorX"
            reg.address = "Addr"
            mock_eui_cls.return_value.oui.registration.return_value = reg
            device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
        host = memory.lan_hosts["AA:BB:CC:DD:EE:FF"]
        assert host.node
        assert "192.168.1.10" in host.node
        assert "AA.BB.CC.DD.EE.FF" in host.node
        assert "VendorX" in host.node


# ───────────────────────── malicious_traffic_identifier ─────────────────────────────

class TestMaliciousTrafficDetection:
    def setup_method(self):
        self.identifier = object.__new__(
            malicious_traffic_identifier.maliciousTrafficIdentifier
        )

    def test_unknown_domain_and_low_port_flagged(self):
        memory.destination_hosts["8.8.8.8"] = DestinationHost(domain_name="NotResolvable")
        assert self.identifier.malicious_traffic_detection("192.168.1.1", "8.8.8.8", 80) == 1

    def test_high_port_flagged(self):
        memory.destination_hosts["8.8.8.8"] = DestinationHost(domain_name="google.com")
        assert self.identifier.malicious_traffic_detection("192.168.1.1", "8.8.8.8", 4444) == 1

    def test_known_domain_low_port_not_flagged(self):
        memory.destination_hosts["8.8.8.8"] = DestinationHost(domain_name="dns.google")
        assert self.identifier.malicious_traffic_detection("192.168.1.1", "8.8.8.8", 53) == 0

    def test_multicast_src_not_flagged(self):
        assert self.identifier.malicious_traffic_detection("224.0.0.1", "8.8.8.8", 9999) == 0

    def test_multicast_dst_not_flagged(self):
        assert self.identifier.malicious_traffic_detection("192.168.1.1", "239.0.0.1", 9999) == 0


class FakePacket:
    """Minimal scapy-like packet stub for covert detection tests."""

    def __init__(self, layers: set, data: dict = None):
        self._layers = layers
        self._data = data or {}

    def __contains__(self, item):
        return item in self._layers

    def __getitem__(self, key):
        return self._data.get(key, MagicMock())


class TestCovertTrafficDetection:
    def test_icmp_with_tcp_in_icmp(self):
        pkt = FakePacket({"ICMP", "TCP in ICMP"})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 1

    def test_icmp_with_udp_in_icmp(self):
        pkt = FakePacket({"ICMP", "UDP in ICMP"})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 1

    def test_icmp_with_dns(self):
        pkt = FakePacket({"ICMP", "DNS"})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 1

    def test_icmp_with_padding(self):
        pkt = FakePacket({"ICMP", "padding"})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 1

    def test_icmp_with_http_payload(self):
        icmp_layer = MagicMock()
        icmp_layer.payload = "HTTP/1.1 200 OK"
        pkt = FakePacket({"ICMP"}, {"ICMP": icmp_layer})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 1

    def test_icmp_clean_returns_zero(self):
        icmp_layer = MagicMock()
        icmp_layer.payload = "data"
        pkt = FakePacket({"ICMP"}, {"ICMP": icmp_layer})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 0

    def test_dns_unresolvable_qname(self):
        dns_layer = MagicMock()
        dns_layer.qd.qname.strip.return_value = b"unresolvable.internal"
        pkt = FakePacket({"DNS"}, {"DNS": dns_layer})
        with patch("communication_details_fetch.trafficDetailsFetch.dns",
                   return_value="NotResolvable"):
            result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt)
        assert result == 1

    def test_dns_high_digit_count_in_qname(self):
        dns_layer = MagicMock()
        dns_layer.qd.qname.strip.return_value = b"aabbcc112233445566.example.com"
        pkt = FakePacket({"DNS"}, {"DNS": dns_layer})
        with patch("communication_details_fetch.trafficDetailsFetch.dns",
                   return_value="NotResolvable"):
            result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt)
        assert result == 1

    def test_normal_packet_returns_zero(self):
        pkt = FakePacket({"TCP", "IP"})
        assert malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(pkt) == 0


class TestCovertPayloadPrediction:
    def test_known_magic_bytes_matched(self):
        memory.signatures = {
            "pdf": {"signs": ["0,25504446"]},  # %PDF
        }
        payload = bytes.fromhex("25504446")
        result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(payload)
        assert "pdf" in result

    def test_empty_payload_returns_empty_list(self):
        memory.signatures = {"pdf": {"signs": ["0,25504446"]}}
        result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(b"")
        assert result == []

    def test_no_match_returns_empty_list(self):
        memory.signatures = {"pdf": {"signs": ["0,25504446"]}}
        result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(b"\x00\x01\x02")
        assert result == []

    def test_malformed_sign_entry_skipped(self):
        memory.signatures = {"broken": {"signs": ["noequalssign"]}}
        result = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(b"\x00")
        assert result == []


class TestMaliciousTrafficIdentifierInit:
    def test_flags_session_with_unknown_domain(self):
        memory.packet_db["192.168.1.1/8.8.8.8/53"] = PacketSession()
        memory.destination_hosts["8.8.8.8"] = DestinationHost(domain_name="NotResolvable")
        malicious_traffic_identifier.maliciousTrafficIdentifier()
        assert "192.168.1.1/8.8.8.8/53" in memory.possible_mal_traffic

    def test_skips_multicast_session(self):
        memory.packet_db["192.168.1.1/224.0.0.1/1234"] = PacketSession()
        malicious_traffic_identifier.maliciousTrafficIdentifier()
        assert len(memory.possible_mal_traffic) == 0

    def test_skips_non_digit_port(self):
        memory.packet_db["192.168.1.1/8.8.8.8/unknown"] = PacketSession()
        malicious_traffic_identifier.maliciousTrafficIdentifier()
        assert len(memory.possible_mal_traffic) == 0


# ────────────────────────────── tor_traffic_handle ──────────────────────────────────

class TestGetConsensusData:
    def test_populates_tor_nodes_on_success(self):
        desc = MagicMock()
        desc.address = "1.2.3.4"
        desc.or_port = 9001
        mock_consensus = MagicMock()
        mock_consensus.run.return_value = [desc]
        with patch("tor_traffic_handle.remote.get_consensus", return_value=mock_consensus):
            tor_traffic_handle.torTrafficHandle()
        assert ("1.2.3.4", 9001) in memory.tor_nodes

    def test_empty_on_consensus_exception(self):
        mock_consensus = MagicMock()
        mock_consensus.run.side_effect = Exception("connection refused")
        with patch("tor_traffic_handle.remote.get_consensus", return_value=mock_consensus):
            tor_traffic_handle.torTrafficHandle()
        assert memory.tor_nodes == []

    def test_skips_download_if_nodes_already_loaded(self):
        memory.tor_nodes.append(("5.6.7.8", 9001))
        with patch("tor_traffic_handle.remote.get_consensus") as mock_get:
            tor_traffic_handle.torTrafficHandle()
        mock_get.assert_not_called()


class TestTorTrafficDetection:
    def test_matching_session_added(self):
        memory.tor_nodes = [("1.2.3.4", 9001)]
        memory.packet_db["10.0.0.1/1.2.3.4/9001"] = {}
        tor = object.__new__(tor_traffic_handle.torTrafficHandle)
        tor.tor_traffic_detection()
        assert "10.0.0.1/1.2.3.4/9001" in memory.possible_tor_traffic

    def test_non_matching_session_not_added(self):
        memory.tor_nodes = [("1.2.3.4", 9001)]
        memory.packet_db["10.0.0.1/5.6.7.8/80"] = {}
        tor = object.__new__(tor_traffic_handle.torTrafficHandle)
        tor.tor_traffic_detection()
        assert len(memory.possible_tor_traffic) == 0

    def test_no_detection_when_tor_nodes_empty(self):
        memory.tor_nodes = []
        memory.packet_db["10.0.0.1/1.2.3.4/9001"] = {}
        tor = object.__new__(tor_traffic_handle.torTrafficHandle)
        tor.tor_traffic_detection()
        assert len(memory.possible_tor_traffic) == 0


# ────────────────────────────── report_generator ────────────────────────────────────

class TestReportGenerator:
    def test_packet_details_creates_file(self, tmp_path):
        memory.packet_db["10.0.0.1/8.8.8.8/53"] = PacketSession(
            Payload={"forward": ["data"], "reverse": []}
        )
        gen = report_generator.reportGen(str(tmp_path), "unit")
        gen.packetDetails()
        out = tmp_path / "Report" / "unit_packet_details.txt"
        assert out.exists()
        assert "10.0.0.1/8.8.8.8/53" in out.read_text()

    def test_communication_details_creates_file(self, tmp_path):
        memory.destination_hosts["8.8.8.8"] = DestinationHost(domain_name="dns.google")
        gen = report_generator.reportGen(str(tmp_path), "unit")
        gen.communicationDetailsReport()
        out = tmp_path / "Report" / "unit_communication_details.txt"
        assert out.exists()
        assert "dns.google" in out.read_text()

    def test_device_details_creates_file(self, tmp_path):
        memory.lan_hosts["AA:BB:CC:DD:EE:FF"] = LanHost(
            ip="192.168.1.5",
            device_vendor="VendorX",
            node="192.168.1.5\nAA.BB.CC.DD.EE.FF\nVendorX",
        )
        gen = report_generator.reportGen(str(tmp_path), "unit")
        gen.deviceDetailsReport()
        out = tmp_path / "Report" / "unit_device_details.txt"
        assert out.exists()
        assert "VendorX" in out.read_text()

    def test_creates_report_directory_if_missing(self, tmp_path):
        gen = report_generator.reportGen(str(tmp_path / "nested" / "path"), "unit")
        gen.packetDetails()
        assert (tmp_path / "nested" / "path" / "Report").is_dir()
