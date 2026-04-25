"""
Interactive network graph — embedded matplotlib+networkx panel to the right of the static map.
Node/edge model mirrors plot_lan_network.py: MAC-based LAN grouping, gateway collapse.
One arc per protocol type per node pair (MultiDiGraph), matching the static graph's edge set.
"""
import logging
import tkinter as tk
from tkinter import ttk

import memory

__all__ = ["gimmick_initialize"]

log = logging.getLogger(__name__)

_container: tk.Frame | None = None
_figure = None
_base: tk.Tk | None = None
_original_geometry: str | None = None

# Width added to the window when the interactive panel is open
_PANEL_WIDTH = 940


def gimmick_initialize(base: tk.Tk, _html_path: str) -> None:
    """Open (or close) the interactive graph panel to the right of the static map."""
    global _container, _figure, _base, _original_geometry

    if _container is not None and _container.winfo_exists():
        _close()
        return

    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("TkAgg")
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    except ImportError as exc:
        log.warning("Interactive graph unavailable — missing dependency: %s", exc)
        import webbrowser
        webbrowser.open(_html_path)
        return

    if not memory.packet_db:
        log.info("Interactive graph: no sessions in memory, nothing to show")
        return

    _base = base

    # ── Build MultiDiGraph — one arc per protocol type per node pair ──────────
    # Node model mirrors plot_lan_network.py: MAC-based LAN grouping,
    # all external destinations collapse to the gateway MAC node.
    G = nx.MultiDiGraph()
    seen_edges: set[tuple] = set()   # (src_label, dst_label, color) — dedup parallel arcs

    for session_key, session in memory.packet_db.items():
        parts = session_key.split("/")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, port = parts

        eth_src = session.Ethernet.get("src", "")
        eth_dst = session.Ethernet.get("dst", "")

        # Source (LAN side — session key always has the private IP as src)
        if eth_src and eth_src in memory.lan_hosts:
            src_label = _mac_label(eth_src)
            src_kind = "lan"
        else:
            src_label = src_ip
            src_kind = "ext"

        # Destination — mirrors plot_lan_network.py exactly
        if dst_ip in memory.destination_hosts:
            dst_mac = memory.destination_hosts[dst_ip].mac
            if dst_mac in memory.lan_hosts:
                dst_label = _mac_label(dst_mac)
                dst_kind = "lan"
            else:
                short = dst_mac[-8:].replace(":", ".") if dst_mac else dst_ip
                dst_label = short + "\nGateway"
                dst_kind = "gw"
        else:
            if eth_dst and eth_dst in memory.lan_hosts:
                dst_label = _mac_label(eth_dst)
                dst_kind = "lan"
            else:
                short = eth_dst[-8:].replace(":", ".") if eth_dst else dst_ip
                dst_label = short + "\nGateway"
                dst_kind = "gw"

        if src_label == dst_label:
            continue

        is_tor = session_key in memory.possible_tor_traffic
        is_mal = session_key in memory.possible_mal_traffic
        color, proto = _edge_attrs(port, session.covert, is_tor, is_mal)

        sig = (src_label, dst_label, color)
        if sig in seen_edges:
            continue
        seen_edges.add(sig)

        G.add_node(src_label, kind=src_kind, ip=src_ip)
        G.add_node(dst_label, kind=dst_kind, ip=dst_ip)
        G.add_edge(src_label, dst_label, color=color, proto=proto)

    if not G.nodes:
        log.info("Interactive graph: nothing to display")
        return

    # ── Layout — same engine selection as plot_lan_network.py ─────────────────
    n_lan = len(memory.lan_hosts)
    prog = "sfdp" if n_lan > 40 else "circo" if n_lan > 20 else "dot"
    try:
        pos = nx.nx_pydot.graphviz_layout(G, prog=prog)
    except Exception as exc:
        log.warning("graphviz_layout failed (%s), falling back to spring_layout", exc)
        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

    # Graphviz returns absolute point coordinates (e.g. x=54, y=36) that matplotlib
    # renders at those literal positions, pushing nodes into a corner.  Normalize
    # to a centered [-1.5, 1.5] range so they always fill the figure.
    pos = _normalize_pos(pos)

    # ── Node colours ──────────────────────────────────────────────────────────
    mal_ips = {s.split("/")[0] for s in memory.possible_mal_traffic} | \
              {s.split("/")[1] for s in memory.possible_mal_traffic}
    tor_ips = {s.split("/")[1] for s in memory.possible_tor_traffic}

    node_colors = []
    for node in G.nodes:
        ip   = G.nodes[node].get("ip", "")
        kind = G.nodes[node].get("kind", "")
        if ip in tor_ips:
            node_colors.append("#9c27b0")   # purple — Tor
        elif ip in mal_ips:
            node_colors.append("#f44336")   # red — malicious
        elif kind == "lan":
            node_colors.append("#1e88e5")   # blue — LAN host
        elif kind == "gw":
            node_colors.append("#78909c")   # gray — gateway/router
        else:
            node_colors.append("#ff7043")   # orange — unknown external

    # Edge colours in MultiDiGraph edge order
    edge_colors = [d.get("color", "#607d8b")
                   for _, _, d in G.edges(data=True)]

    # ── Matplotlib figure ─────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("#1e1e2e")
    ax.set_facecolor("#1e1e2e")

    nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                           node_size=700, alpha=0.92, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=6,
                            font_color="white", ax=ax)
    # MultiDiGraph: draw_networkx_edges fans parallel arcs automatically
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors,
                           arrows=True, arrowsize=14,
                           connectionstyle="arc3,rad=0.15",
                           ax=ax, alpha=0.85)

    _add_legend(ax)
    ax.margins(0.2)        # 20% padding around the data bounds
    ax.axis("off")
    # tight_layout squishes axes when there's a legend; use subplots_adjust instead
    fig.subplots_adjust(left=0.02, right=0.98, top=0.98, bottom=0.02)

    # ── Expand window and embed panel to the right of ThirdFrame ─────────────
    _original_geometry = base.geometry()
    try:
        wh, ox, oy = _original_geometry.split("+")
        ow, oh = wh.split("x")
        base.geometry(f"{int(ow) + _PANEL_WIDTH}x{oh}+{ox}+{oy}")
    except Exception:
        log.warning("Could not parse geometry %s", _original_geometry)

    _container = tk.Frame(base, bg="#1e1e2e")
    _container.grid(row=40, column=11, sticky="nsew", padx=(6, 6), pady=(0, 6))
    _container.rowconfigure(1, weight=1)
    _container.columnconfigure(0, weight=1)

    # Toolbar row
    toolbar_row = tk.Frame(_container, bg="#2e2e3e")
    toolbar_row.grid(row=0, column=0, sticky="ew")

    canvas_widget = FigureCanvasTkAgg(fig, master=_container)
    nav = NavigationToolbar2Tk(canvas_widget, toolbar_row, pack_toolbar=False)
    nav.update()
    nav.pack(side=tk.LEFT)
    ttk.Button(toolbar_row, text="Close", command=_close).pack(
        side=tk.RIGHT, padx=4, pady=2)

    canvas_widget.get_tk_widget().grid(row=1, column=0, sticky="nsew")

    # Info bar
    info_var = tk.StringVar(value="Click a node for details  |  "
                                  "Blue=LAN  Gray=Gateway  Red=Malicious  Purple=Tor")
    ttk.Label(_container, textvariable=info_var, anchor="w",
              padding=(6, 3)).grid(row=2, column=0, sticky="ew")

    canvas_widget.draw()

    # Click-to-inspect
    def _on_click(event):
        if event.inaxes != ax or event.xdata is None:
            return
        closest, min_dist = None, float("inf")
        for node, (x, y) in pos.items():
            d = (event.xdata - x) ** 2 + (event.ydata - y) ** 2
            if d < min_dist:
                min_dist, closest = d, node
        if closest is None or min_dist > 0.25:
            return
        ip = G.nodes[closest].get("ip", "?")
        sessions = [s for s in memory.packet_db if ip in s.split("/")[:2]]
        dst_host = memory.destination_hosts.get(ip)
        domain = dst_host.domain_name if dst_host and dst_host.domain_name else "—"
        protos = sorted({G[u][v][k].get("proto", "")
                         for u, v, k in G.edges(keys=True)
                         if u == closest or v == closest})
        info_var.set(
            f"Node: {closest}  |  IP: {ip}  |  Domain: {domain}  |  "
            f"Sessions: {len(sessions)}  |  Protocols: {', '.join(protos)}"
        )

    fig.canvas.mpl_connect("button_press_event", _on_click)
    _figure = fig


def _normalize_pos(pos: dict) -> dict:
    """Center and scale graphviz positions to a [-1.5, 1.5] range.

    graphviz_layout returns absolute point coordinates (e.g. x=54, y=36).
    Without normalization matplotlib renders nodes at those literal positions,
    which places them in a tiny corner of the figure.
    """
    if len(pos) <= 1:
        return {n: (0.0, 0.0) for n in pos}
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    cx = (max(xs) + min(xs)) / 2
    cy = (max(ys) + min(ys)) / 2
    rng = max(max(xs) - min(xs), max(ys) - min(ys)) or 1.0
    return {n: ((x - cx) / rng * 1.5, (y - cy) / rng * 1.5)
            for n, (x, y) in pos.items()}


def _mac_label(mac: str) -> str:
    """Node label for a LAN host — mirrors plot_lan_network._node_label()."""
    h = memory.lan_hosts[mac]
    return h.node if h.node else h.ip


def _edge_attrs(port: str, covert: bool, is_tor: bool, is_mal: bool) -> tuple[str, str]:
    """Return (hex_color, protocol_name) for an edge."""
    if is_mal:
        return "#f44336", "Malicious"
    if is_tor:
        return "#9c27b0", "Tor"
    if covert:
        proto = "DNS" if port == "53" else port
        return "#00bcd4", f"Covert/{proto}"
    if port == "443":
        return "#1e88e5", "HTTPS"
    if port == "80":
        return "#43a047", "HTTP"
    if port == "53":
        return "#fdd835", "DNS"
    if port == "ICMP":
        return "#ff7043", "ICMP"
    try:
        if int(port) in (20, 21, 23, 25, 110, 143, 139, 69, 161, 162, 1521):
            return "#ce93d8", f"Clear/{port}"
    except ValueError:
        pass
    return "#607d8b", f"Port {port}"


def _add_legend(ax) -> None:
    import matplotlib.patches as mpatches
    from matplotlib.lines import Line2D
    items = [
        mpatches.Patch(color="#1e88e5", label="LAN host"),
        mpatches.Patch(color="#78909c", label="Gateway"),
        mpatches.Patch(color="#f44336", label="Malicious"),
        mpatches.Patch(color="#9c27b0", label="Tor"),
        Line2D([0], [0], color="#1e88e5", linewidth=2, label="HTTPS"),
        Line2D([0], [0], color="#43a047", linewidth=2, label="HTTP"),
        Line2D([0], [0], color="#fdd835", linewidth=2, label="DNS"),
        Line2D([0], [0], color="#00bcd4", linewidth=2, label="Covert"),
    ]
    ax.legend(handles=items, loc="upper left",
              facecolor="#2e2e3e", edgecolor="#555", labelcolor="white",
              fontsize=6, ncol=2)


def _close() -> None:
    global _container, _figure, _base, _original_geometry
    import matplotlib.pyplot as plt
    if _figure is not None:
        plt.close(_figure)
        _figure = None
    if _container is not None and _container.winfo_exists():
        _container.destroy()
        _container = None
    if _base is not None and _original_geometry is not None:
        _b, _geom = _base, _original_geometry
        _b.after(50, lambda: _b.geometry(_geom))
    _base = None
    _original_geometry = None
