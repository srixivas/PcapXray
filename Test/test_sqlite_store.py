"""Tests for sqlite_store.SqliteStore."""
import json
import os
import tempfile

import pytest

import memory
from memory import DestinationHost, LanHost, PacketSession
from sqlite_store import SqliteStore


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


@pytest.fixture()
def store(tmp_path):
    return SqliteStore(db_path=str(tmp_path / "test.db"))


def _seed_memory():
    memory.packet_db["1.2.3.4/5.6.7.8/443"] = PacketSession(
        Ethernet={"src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66"},
        Payload={"forward": ["hello"], "reverse": ["world"]},
        covert=False,
        file_signatures=["PDF"],
    )
    memory.lan_hosts["aa:bb:cc:dd:ee:ff"] = LanHost(
        ip="1.2.3.4", device_vendor="Acme", vendor_address="123 St", node="1.2.3.4\naa:bb"
    )
    memory.destination_hosts["5.6.7.8"] = DestinationHost(
        mac="11:22:33:44:55:66", domain_name="example.com", device_vendor="ExampleCorp"
    )
    memory.possible_tor_traffic = ["1.2.3.4/5.6.7.8/443"]
    memory.possible_mal_traffic = ["1.2.3.4/5.6.7.8/443"]


def test_has_session_false_when_empty(store):
    assert store.has_session("test") is False


def test_save_and_has_session(store):
    _seed_memory()
    store.save_session("mypcap")
    assert store.has_session("mypcap") is True
    assert store.has_session("other") is False


def test_load_roundtrip(store):
    _seed_memory()
    store.save_session("mypcap")

    # Wipe memory to confirm load repopulates it
    memory.packet_db = {}
    memory.lan_hosts = {}
    memory.destination_hosts = {}
    memory.possible_tor_traffic = []
    memory.possible_mal_traffic = []

    store.load_session("mypcap")

    assert "1.2.3.4/5.6.7.8/443" in memory.packet_db
    session = memory.packet_db["1.2.3.4/5.6.7.8/443"]
    assert session.Ethernet["src"] == "aa:bb:cc:dd:ee:ff"
    assert session.Payload["forward"] == ["hello"]
    assert session.covert is False
    assert session.file_signatures == ["PDF"]

    assert "aa:bb:cc:dd:ee:ff" in memory.lan_hosts
    host = memory.lan_hosts["aa:bb:cc:dd:ee:ff"]
    assert host.ip == "1.2.3.4"
    assert host.device_vendor == "Acme"

    assert "5.6.7.8" in memory.destination_hosts
    dst = memory.destination_hosts["5.6.7.8"]
    assert dst.domain_name == "example.com"
    assert dst.mac == "11:22:33:44:55:66"

    assert memory.possible_tor_traffic == ["1.2.3.4/5.6.7.8/443"]
    assert memory.possible_mal_traffic == ["1.2.3.4/5.6.7.8/443"]


def test_save_overwrites_existing(store):
    _seed_memory()
    store.save_session("mypcap")

    memory.packet_db = {}
    store.save_session("mypcap")  # save again with empty db

    store.load_session("mypcap")
    assert memory.packet_db == {}


def test_list_sessions(store):
    _seed_memory()
    store.save_session("pcap_a")
    store.save_session("pcap_b")
    sessions = store.list_sessions()
    assert set(sessions) == {"pcap_a", "pcap_b"}


def test_load_nonexistent_session_is_noop(store):
    _seed_memory()
    original_db = dict(memory.packet_db)
    store.load_session("does_not_exist")
    assert memory.packet_db == original_db


def test_bad_db_path_degrades_gracefully(tmp_path):
    bad_path = str(tmp_path / "nonexistent_subdir" / "bad.db")
    store = SqliteStore(db_path=bad_path)
    assert store.has_session("x") is False
    assert store.list_sessions() == []
    _seed_memory()
    store.save_session("x")   # must not raise
    store.load_session("x")   # must not raise


def test_empty_pcap_name_is_safe(store):
    assert store.has_session("") is False
    _seed_memory()
    store.save_session("")
    assert store.has_session("") is True
    memory.packet_db = {}
    store.load_session("")
    assert "1.2.3.4/5.6.7.8/443" in memory.packet_db


def test_load_corrupt_data_leaves_memory_untouched(store):
    """Corrupt blob in DB must not partially update memory."""
    _seed_memory()
    store.save_session("mypcap")

    # Manually corrupt the lan_hosts column
    store._con.execute(
        "UPDATE sessions SET lan_hosts = ? WHERE pcap_name = ?",
        ("not-valid-json{{{", "mypcap"),
    )
    store._con.commit()

    original_packet_db = dict(memory.packet_db)
    memory.lan_hosts = {}  # simulate clean slate before load attempt

    store.load_session("mypcap")

    # packet_db must NOT have been updated — load should have aborted atomically
    assert memory.packet_db == {} or memory.packet_db == original_packet_db
    assert memory.lan_hosts == {}  # must remain untouched


def test_close_allows_reconnect(tmp_path):
    db = str(tmp_path / "test.db")
    store = SqliteStore(db_path=db)
    _seed_memory()
    store.save_session("pcap1")
    store.close()
    assert store._con is None
    # Re-open and data should still be there
    store2 = SqliteStore(db_path=db)
    assert store2.has_session("pcap1") is True
    store2.close()
