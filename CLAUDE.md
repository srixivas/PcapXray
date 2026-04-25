# PcapXray — Claude Guidelines

## What this project is

PcapXray is a network forensics and visualization tool. It reads PCAP files, classifies sessions by protocol, detects covert/malicious/Tor traffic, resolves hostnames and OUI vendor info, then renders a graph of the LAN network. It has a Tkinter GUI and a CLI entrypoint (`Source/main.py`).

Target runtime: **Python 3.10+**. Python 2 support was dropped; never reintroduce Py2 shims.

---

## Architecture

### Data flow (one pass through the PCAP)
```
pcap_reader.PcapEngine          — reads PCAP → populates memory state
    ↓
communication_details_fetch     — DNS/whois reverse-lookup on destination IPs
device_details_fetch            — OUI vendor lookup on LAN MACs
tor_traffic_handle              — Tor consensus download + session match
malicious_traffic_identifier    — flags sessions by port/domain heuristic
    ↓
plot_lan_network.PlotLan        — renders graphviz PNG (+ pyvis HTML)
report_generator.ReportGenerator— writes TXT reports
    ↓
user_interface.pcapXrayGui      — Tkinter GUI driving all of the above
```

### Global state (memory.py)
All inter-module state lives in `memory.py` as typed Pydantic models inside plain dict containers:

| Container | Key | Value type |
|---|---|---|
| `memory.packet_db` | `"src/dst/port"` | `PacketSession` |
| `memory.lan_hosts` | MAC string | `LanHost` |
| `memory.destination_hosts` | IP string | `DestinationHost` |
| `memory.tor_nodes` | — | `list[tuple[str, int]]` |
| `memory.possible_tor_traffic` | — | `list[str]` |
| `memory.possible_mal_traffic` | — | `list[str]` |

**Never use dict-style key access on model values.** Use attribute access: `session.covert`, `host.domain_name`, `h.node`. The models guarantee field presence so `.get()` fallbacks are not needed.

---

## Coding conventions

### Module structure
Every source module must have:
- `__all__` listing its public API (at the top, after docstring/imports)
- `log = logging.getLogger(__name__)` — never use `print()` or bare `logging.*` calls
- Type hints on all function signatures

### Class naming
PEP 8 CamelCase: `TrafficDetailsFetch`, `FetchDeviceDetails`, `MaliciousTrafficIdentifier`, `TorTrafficHandle`, `ReportGenerator`, `PlotLan`, `PcapEngine`. Internal helpers are `_snake_case`.

### Logging
- Use `PCAPXRAY_DEBUG=1` env var to enable DEBUG level (wired in `Source/main.py`)
- Log file: `~/PcapXray.log` (overwritten each run)
- Pattern: `log.info("...")`, `log.warning("...")`, `log.error("...")`

### Error handling
- Never use bare `except:` — always `except Exception:` or a specific type
- External I/O (DNS, Tor, OUI APIs) must have timeouts and degrade gracefully
- DNS batch: `concurrent.futures.wait(timeout=10.0)` hard cap
- Tor consensus: daemon thread + `join(timeout=15.0)`
- Graphviz render: `f.render(timeout=30)` with `except TypeError` fallback for older lib versions

### Pydantic models
- Models live in `memory.py`; import them where needed: `from memory import PacketSession, LanHost, DestinationHost`
- When serializing to JSON (reports), use `_ModelEncoder` from `report_generator.py` or call `.model_dump()` explicitly
- Model fields have safe defaults — no need to guard with `if "key" not in dict`

---

## Testing

### Running tests
```bash
# Fast suite — no network calls (~45s)
pytest -m "not network" Test/

# Full suite including real DNS + Tor (~95s locally, may be slow in CI)
pytest Test/
```

### Test layout
| File | What it tests |
|---|---|
| `Test/test_unit.py` | Per-module unit tests with mocked network/OUI/Tor |
| `Test/test_sanity.py` | End-to-end smoke tests against real PCAP files |
| `Test/test_pcap_reader_module.py` | Standalone pcap_reader smoke test |

### Markers
- `@pytest.mark.network` — marks tests that make real network calls (DNS resolution, Tor consensus). These are skipped in CI with `-m "not network"`.

### conftest.py
Located at project root. Adds `Source/Module` to `sys.path` and exports `EXAMPLES_DIR` pointing to `Source/Module/examples/`. All tests import from there — never hardcode paths.

### Writing new tests
- Seed `memory.*` with model instances, not raw dicts: `memory.destination_hosts["1.2.3.4"] = DestinationHost(domain_name="example.com")`
- Reset memory state in a `@pytest.fixture(autouse=True)` — see `test_unit.py` for the pattern
- Mock at the module level: `patch("communication_details_fetch.socket.gethostbyaddr", ...)`
- 65+ tests must stay green before any commit

---

## Things to avoid

- **No Python 2 shims** — no `try/except ImportError` for `tkinter`/`Tkinter`, `queue`/`Queue`, etc.
- **No `cefpython3`** — removed; no Python 3.10 wheel exists. Phase 4 will replace with `pywebview`.
- **No `print()` in source modules** — use `log.*`
- **No bare `except:`** — always catch `Exception` or a specific type
- **No dict-style access on Pydantic model values** — use attribute access
- **No `netaddr.IPAddress.is_private()`** — removed in netaddr 0.9.x; use `ipaddress.ip_address(ip).is_private` (stdlib, property not method)
- **No blocking calls on the Tkinter main thread** — use `_run_in_thread()` / `_poll_thread()` from `user_interface.py`
- **No pushing many small commits to remote** — batch related changes locally and push once per logical unit of work

---

## Phased roadmap (current state)

| Phase | Status | Notes |
|---|---|---|
| 0 — Critical bug fixes | Done | Pillow ANTIALIAS, is_private(), urllib, bare excepts |
| 1 — Python 2 drop + deps | Done | Py3-only imports, requirements.txt pinned |
| 2 — Test infrastructure | Done | conftest.py, 65 tests, network marker, coverage in CI |
| 3 — Code quality | Done | Pydantic models, PEP 8 names, `__all__`, logging, dead code |
| 4 — Replace cefpython3 | Pending | Use `pywebview` (OS-native webview); see `interactive_gui.py` |
| 5 — Features | Pending | Streaming PCAP, more protocols, web UI, SQLite backend |

### Phase 4 specifics
`interactive_gui.py` currently uses `cefpython3` which segfaults on macOS and has no Python 3.10 wheel. The replacement plan:
- Use `pywebview` — `webview.create_window(title, html=html_content)` then `webview.start()`
- The pyvis HTML output from `PlotLan` is the content to pass in
- Target: rewrite `interactive_gui.py` to under 80 lines

---

## CI (GitHub Actions)

Workflow: `.github/workflows/test.yml`
- Matrix: Python 3.10, 3.11, 3.12
- System deps: `graphviz python3-tk tshark` via apt
- Test command: `pytest -m "not network" --cov=Source/Module --cov-report=xml Test/`
- Coverage uploaded to Codecov (requires `CODECOV_TOKEN` secret in repo settings)
- Lint: `flake8` — fatal errors only (E9, F63, F7, F82); style issues are advisory
