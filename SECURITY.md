# PcapXray — Security Guidelines

This document defines security expectations for anyone (human or AI agent) contributing code or building features on this project.

---

## Threat model

PcapXray is a local forensics tool. It has no network-facing surface — no web server, no API, no daemon. The primary attack surface is:

- **Malicious PCAP files** — crafted packets could trigger bugs in parsing libraries
- **DNS/whois responses** — untrusted external data used for hostname resolution
- **File paths** — user-supplied PCAP and output directory paths

---

## Rules for contributors and agents

### Input handling
- Validate all file paths before opening — check existence and read permissions before passing to any parser
- Never pass unsanitised user input to `subprocess`, `eval`, or `os.system`
- All IP addresses must be parsed with `ipaddress.ip_address()` — never string-manipulate IPs for classification
- DNS/whois results are untrusted — treat them as display strings only, never execute or eval them

### External calls
- All DNS lookups must use the `concurrent.futures` batch pattern with a hard `timeout=10.0` cap — no unbounded blocking calls on the main thread
- Tor consensus fetches must run in a daemon thread with `join(timeout=15.0)`
- Graphviz rendering must use `timeout=30` on the render call
- Any new external API call must degrade gracefully — catch `Exception`, log, return a safe default

### Privileges
- Live capture requires root — never attempt to escalate privileges programmatically
- Never store sensitive data (keys, credentials, tokens) in memory models, SQLite, or reports
- Output files (PNG, HTML, reports) go only to the user-specified output directory — no writes outside it

### Dependencies
- Do not add new dependencies without checking for known CVEs
- Prefer stdlib over third-party for security-sensitive operations (use `ipaddress`, `hashlib`, `ssl` from stdlib)
- Never introduce a dependency that requires a network service or phone-home behaviour

### Concurrency and race conditions
- All `memory.*` mutations in `LivePcapEngine._on_packet` must be inside `self._lock` — the sniffer runs on a separate thread
- Never read-modify-write `memory.*` containers from multiple threads without the lock
- Never schedule blocking calls directly on the Tk main thread — use `_run_in_thread` + `_poll_thread`
- Never share mutable state between threads without synchronisation — use `threading.Lock` or pass copies

### Secret handling
- Never log, print, or include in reports: passwords, API keys, tokens, or raw payload bytes that may contain credentials
- PCAP payloads may contain sensitive user data — store only what is needed for analysis (signatures, protocol flags), not raw content
- SQLite session files may contain IP addresses and hostnames — do not sync them to cloud storage or commit them to git

### Code patterns to avoid
- No `pickle` for serialisation — use JSON or Pydantic `.model_dump()`
- No `shell=True` in `subprocess` calls
- No bare `except:` — always `except Exception:` or a specific type
- No hardcoded credentials, tokens, or API keys anywhere in the codebase

---

## Reporting

This is a personal open-source project — there is no formal CVE process. If you find a security issue, open a GitHub issue or submit a PR with a fix.

https://github.com/srixivas/PcapXray/issues
