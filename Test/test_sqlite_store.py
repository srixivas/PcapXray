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


def test_bad_db_path_degrades_gracefully():
    store = SqliteStore(db_path="/nonexistent_dir/bad.db")
    assert store.has_session("x") is False
    assert store.list_sessions() == []
    _seed_memory()
    store.save_session("x")   # must not raise
    store.load_session("x")   # must not raise
