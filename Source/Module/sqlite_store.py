"""
Module sqlite_store — SQLite session persistence for PcapXray.

Saves the full analysis state (packet_db, lan_hosts, destination_hosts,
tor/malicious traffic lists) to a local SQLite DB keyed by PCAP filename.
On re-analysis of the same file, the GUI can offer to reload from the cache
instead of re-parsing the PCAP.

Inspired by PR #70 (Matt Bernardo / Technica Corporation).
"""
__all__ = ["SqliteStore"]

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

import memory
from memory import DestinationHost, LanHost, PacketSession

log = logging.getLogger(__name__)

_DEFAULT_DB = os.path.join(os.path.expanduser("~"), "PcapXray_sessions.db")

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    pcap_name   TEXT PRIMARY KEY,
    saved_at    TEXT NOT NULL,
    packet_db   TEXT NOT NULL,
    lan_hosts   TEXT NOT NULL,
    dest_hosts  TEXT NOT NULL,
    tor_traffic TEXT NOT NULL,
    mal_traffic TEXT NOT NULL
);
"""


class SqliteStore:
    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        self._con: sqlite3.Connection | None = None
        try:
            self._con = sqlite3.connect(self._db_path)
            self._con.execute(_DDL)
            self._con.commit()
            log.info("SqliteStore: connected to %s", self._db_path)
        except Exception as exc:
            log.error("SqliteStore: failed to open DB: %s", exc)
            self._con = None

    def has_session(self, pcap_name: str) -> bool:
        if self._con is None:
            return False
        try:
            cur = self._con.execute(
                "SELECT 1 FROM sessions WHERE pcap_name = ?", (pcap_name,)
            )
            return cur.fetchone() is not None
        except Exception as exc:
            log.warning("SqliteStore.has_session: %s", exc)
            return False

    def save_session(self, pcap_name: str) -> None:
        if self._con is None:
            return
        try:
            self._con.execute(
                """
                INSERT OR REPLACE INTO sessions
                    (pcap_name, saved_at, packet_db, lan_hosts, dest_hosts,
                     tor_traffic, mal_traffic)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pcap_name,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps({k: v.model_dump() for k, v in memory.packet_db.items()}),
                    json.dumps({k: v.model_dump() for k, v in memory.lan_hosts.items()}),
                    json.dumps({k: v.model_dump() for k, v in memory.destination_hosts.items()}),
                    json.dumps(memory.possible_tor_traffic),
                    json.dumps(memory.possible_mal_traffic),
                ),
            )
            self._con.commit()
            log.info("SqliteStore: saved session '%s' (%d packet sessions)",
                     pcap_name, len(memory.packet_db))
        except Exception as exc:
            log.error("SqliteStore.save_session: %s", exc)

    def load_session(self, pcap_name: str) -> None:
        if self._con is None:
            return
        try:
            cur = self._con.execute(
                """
                SELECT packet_db, lan_hosts, dest_hosts, tor_traffic, mal_traffic
                FROM sessions WHERE pcap_name = ?
                """,
                (pcap_name,),
            )
            row = cur.fetchone()
            if row is None:
                log.warning("SqliteStore.load_session: '%s' not found", pcap_name)
                return
            memory.packet_db = {
                k: PacketSession.model_validate(v)
                for k, v in json.loads(row[0]).items()
            }
            memory.lan_hosts = {
                k: LanHost.model_validate(v)
                for k, v in json.loads(row[1]).items()
            }
            memory.destination_hosts = {
                k: DestinationHost.model_validate(v)
                for k, v in json.loads(row[2]).items()
            }
            memory.possible_tor_traffic = json.loads(row[3])
            memory.possible_mal_traffic = json.loads(row[4])
            log.info(
                "SqliteStore: loaded session '%s' (%d sessions, %d LAN hosts, %d dest hosts)",
                pcap_name, len(memory.packet_db), len(memory.lan_hosts), len(memory.destination_hosts),
            )
        except Exception as exc:
            log.error("SqliteStore.load_session: %s", exc)

    def list_sessions(self) -> list[str]:
        if self._con is None:
            return []
        try:
            cur = self._con.execute(
                "SELECT pcap_name FROM sessions ORDER BY saved_at DESC"
            )
            return [row[0] for row in cur.fetchall()]
        except Exception as exc:
            log.warning("SqliteStore.list_sessions: %s", exc)
            return []
