# PcapXray — Developer Reference

Architecture, call flows, threading model, and extension points.

---

## Repository Layout

```
PcapXray/
├── Source/
│   ├── main.py                        # Entry point
│   └── Module/
│       ├── user_interface.py          # Tkinter GUI controller
│       ├── interactive_gui.py         # Matplotlib panel (live + static)
│       ├── pcap_reader.py             # PcapEngine + LivePcapEngine
│       ├── memory.py                  # Shared state (Pydantic models)
│       ├── engines/                   # Pluggable PCAP parsers
│       │   ├── __init__.py            # select_engine()
│       │   ├── base.py                # NormalizedPacket + PacketEngine protocol
│       │   ├── scapy_engine.py        # TLS-aware streaming engine
│       │   ├── dpkt_engine.py         # Fast offline engine
│       │   └── pyshark_engine.py      # tshark-backed engine
│       ├── plot_lan_network.py        # Graphviz PNG + pyvis HTML
│       ├── communication_details_fetch.py  # DNS + whois
│       ├── device_details_fetch.py    # OUI vendor lookup
│       ├── tor_traffic_handle.py      # Tor consensus download + match
│       ├── malicious_traffic_identifier.py # Heuristic flagging
│       ├── sqlite_store.py            # Session persistence
│       └── report_generator.py       # Text report writer
├── Test/
│   ├── conftest.py
│   ├── test_unit.py
│   ├── test_sanity.py
│   ├── test_engines.py
│   ├── test_pcap_reader_module.py
│   └── test_sqlite_store.py
├── CLAUDE.md                          # Claude Code guidelines
├── DEV.md                             # This file
├── SECURITY.md                        # Security policy
└── tox.ini
```

---

## Global State — memory.py

All inter-module state lives as Pydantic models in plain dict containers:

| Container | Key | Value type | Description |
|---|---|---|---|
| `memory.packet_db` | `"src/dst/port"` | `PacketSession` | All captured sessions |
| `memory.lan_hosts` | MAC string | `LanHost` | Devices on the local network |
| `memory.destination_hosts` | IP string | `DestinationHost` | External/remote hosts |
| `memory.tor_nodes` | — | `list[tuple[str,int]]` | Tor consensus node list |
| `memory.possible_tor_traffic` | — | `list[str]` | Session keys flagged as Tor |
| `memory.possible_mal_traffic` | — | `list[str]` | Session keys flagged as malicious |

**Rule:** always use attribute access on model values (`session.covert`, `host.domain_name`). Never dict-style access.

Memory is the live source of truth. SQLite is persistence. The matplotlib panel and static graph both read from memory at render time.

---

## File Analysis Flow

```mermaid
sequenceDiagram
    participant UI as user_interface
    participant PR as pcap_reader.PcapEngine
    participant ENG as engines/
    participant MEM as memory
    participant CDF as communication_details_fetch
    participant DDF as device_details_fetch
    participant TTH as tor_traffic_handle
    participant MTI as malicious_traffic_identifier
    participant SS as sqlite_store
    participant PLN as plot_lan_network

    UI->>PR: PcapEngine(file, engine)
    PR->>ENG: select_engine(name, path)
    loop each packet
        ENG-->>PR: NormalizedPacket
        PR->>MEM: _process_packet() → packet_db, lan_hosts, destination_hosts
    end
    PR->>PR: _run_deferred_covert() — batch DNS check
    PR-->>UI: complete

    UI->>CDF: TrafficDetailsFetch(option)
    CDF->>MEM: update destination_hosts.domain_name
    UI->>DDF: FetchDeviceDetails()
    DDF->>MEM: update lan_hosts.vendor
    UI->>TTH: TorTrafficHandle()
    TTH->>MEM: populate tor_nodes, possible_tor_traffic
    UI->>MTI: MaliciousTrafficIdentifier()
    MTI->>MEM: populate possible_mal_traffic

    UI->>SS: save_session(name)
    UI->>PLN: PlotLan() → PNG + HTML
    UI->>UI: load_image() — display PNG in canvas
```

---

## Live Capture Flow

```mermaid
sequenceDiagram
    participant UI as user_interface
    participant LPE as pcap_reader.LivePcapEngine
    participant SNF as scapy AsyncSniffer
    participant MEM as memory
    participant IG as interactive_gui
    participant SS as sqlite_store
    participant PLN as plot_lan_network

    UI->>LPE: LivePcapEngine(iface) — resets memory
    UI->>LPE: start()
    LPE->>SNF: AsyncSniffer(iface, prn=_on_packet)

    loop every packet (sniffer thread)
        SNF-->>LPE: _on_packet(raw)
        LPE->>LPE: _normalize() → NormalizedPacket
        LPE->>MEM: _process_packet() [under Lock]
    end

    loop every 4s (Tk main thread)
        UI->>IG: refresh_live()
        IG->>MEM: _build_graph_data(live=True)
        IG->>IG: spring_layout + redraw axes
    end

    UI->>LPE: stop()
    LPE->>SNF: stop + join
    LPE->>LPE: _run_deferred_covert() — batch DNS
    LPE-->>UI: complete

    UI->>SS: save_session(name)
    Note over UI: Visualize! now available
    UI->>PLN: PlotLan() — point-in-time snapshot
```

---

## Pluggable Engine Architecture

```mermaid
graph LR
    SE[select_engine\nauto/dpkt/scapy/pyshark] --> DE[DpktEngine]
    SE --> SCE[ScapyEngine]
    SE --> PSE[PySharkEngine]
    DE --> NP[NormalizedPacket]
    SCE --> NP
    PSE --> NP
    NP --> PP[_process_packet]
    PP --> MEM[(memory.*)]
```

All engines implement the `PacketEngine` protocol from `engines/base.py`:

```python
class PacketEngine(Protocol):
    def stream(self) -> Iterator[NormalizedPacket]: ...
```

`NormalizedPacket` is a dataclass with fields: `ip_version`, `src_ip`, `dst_ip`, `src_mac`, `dst_mac`, `proto`, `src_port`, `dst_port`, `payload_bytes`, `tls_records`, `dns_qname`, `icmp_tunneled`.

### Adding a new engine

1. Create `engines/your_engine.py` implementing `stream() -> Iterator[NormalizedPacket]`
2. Register it in `engines/__init__.py` inside `select_engine()`
3. Add `skipif` tests to `Test/test_engines.py` following the dpkt pattern

---

## Threading Model

```mermaid
graph TD
    TK[Tk main thread] -->|after 4s| LR[_live_refresh]
    TK -->|_run_in_thread| BG[background thread\nengine.stop / PlotLan / DNS]
    BG -->|_poll_thread loop| TK
    SNF[scapy sniffer thread] -->|Lock| MEM[(memory.*)]
    TK -->|reads| MEM
```

- `LivePcapEngine._on_packet` runs in scapy's sniffer thread; all `memory.*` mutations are protected by `self._lock`
- All blocking operations (DNS, graphviz render, covert check) run via `_run_in_thread` + `_poll_thread` to keep the Tk main thread responsive
- `_live_refresh` reads from memory on the Tk main thread — safe because it only reads, never writes

---

## Session Key Format

```
"src_ip/dst_ip/port"
```

- TCP/UDP private→public: `"192.168.1.10/8.8.8.8/443"`
- ICMP: `"192.168.1.10/8.8.8.8/ICMP"`
- Both private: bidirectional dedup — key2 reused if it already exists

---

## Covert Channel Detection

Two-stage:

1. **Inline** (during packet loop): ICMP with tunneled payload → `session.covert = True` immediately. DNS qnames with >8 digits → `session.covert = True` immediately.
2. **Deferred** (`_run_deferred_covert`): DNS qnames queued during capture are batch-resolved after the loop ends. Unresolvable qnames → `session.covert = True`. Deduplicated by qname — one DNS call per unique qname regardless of session count. Hard cap: 10s wall-clock timeout.

---

## SQLite Session Cache

`sqlite_store.SqliteStore` serialises all `memory.*` state to a local SQLite database. On next open, if a matching session exists the UI offers to load from cache (skipping re-analysis). Live capture sessions are saved automatically on stop with a timestamp-based name: `live_{iface}_{timestamp}`.

---

## Test Layout

| File | Coverage |
|------|---------|
| `test_unit.py` | Per-module unit tests, mocked network/OUI/Tor |
| `test_sanity.py` | End-to-end smoke tests against real PCAP files |
| `test_pcap_reader_module.py` | PcapEngine standalone smoke test |
| `test_engines.py` | NormalizedPacket, all engines, `_process_packet`, `LivePcapEngine` lifecycle |
| `test_sqlite_store.py` | Session persistence and reload |

Run with `pytest -m "not network" Test/` to skip tests that make real DNS/Tor calls.

---

## Environment Variables

| Variable | Effect |
|----------|--------|
| `PCAPXRAY_DEBUG=1` | Enable DEBUG log level |

Log file: `~/PcapXray.log` (overwritten each run).
