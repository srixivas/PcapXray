"""
Interactive network graph — embedded matplotlib+networkx panel to the right of the static map.
Node/edge model mirrors plot_lan_network.py: MAC-based LAN grouping, gateway collapse.
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

# Edge color priority (higher = more notable, wins when collapsing parallel edges)
_EDGE_PRIORITY = {
    "#f44336": 6,   # malicious — red
    "#9c27b0": 5,   # Tor — purple
    "#00bcd4": 4,   # covert — cyan
    "#43a047": 3,   # HTTP — green
    "#1e88e5": 3,   # HTTPS — blue
    "#fdd835": 2,   # DNS — yellow
    "#ff7043": 2,   # ICMP — orange
    "#607d8b": 1,   # other — gray
}


def gimmick_initialize(base: tk.Tk, _html_path: str) -> None:
    """Open (or close) the interactive graph panel to the right of the static map.

    Called by user_interface.pcapXrayGui.gimmick().  The html_path arg is kept
    for API compatibility only.
    """
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

    # ── Build graph (same MAC-based node model as plot_lan_network.py) ────────
    G = nx.DiGraph()

    for session_key, session in memory.packet_db.items():
        parts = session_key.split("/")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, port = parts

        eth_src = session.Ethernet.get("src", "")
        eth_dst = session.Ethernet.get("dst", "")

        # Source node — LAN side (session key always has private IP as src)
        if eth_src and eth_src in memory.lan_hosts:
            src_label = _mac_label(eth_src)
            src_kind = "lan"
        else:
            src_label = src_ip
            src_kind = "ext"

        # Destination node — mirror plot_lan_network.py exactly
        if dst_ip in memory.destination_hosts:
            dst_mac = memory.destination_hosts[dst_ip].mac
            if dst_mac in memory.lan_hosts:
                dst_label = _mac_label(dst_mac)
                dst_kind = "lan"
            else:
                short_mac = dst_mac.replace(":", ".")[-11:] if dst_mac else dst_ip
                dst_label = short_mac + "\nGateway"
                dst_kind = "gw"
        else:
            if eth_dst and eth_dst in memory.lan_hosts:
                dst_label = _mac_label(eth_dst)
                dst_kind = "lan"
            else:
                short_mac = eth_dst.replace(":", ".")[-11:] if eth_dst else dst_ip
                dst_label = short_mac + "\nGateway"
                dst_kind = "gw"

        if src_label == dst_label:
            continue

        is_tor = session_key in memory.possible_tor_traffic
        is_mal = session_key in memory.possible_mal_traffic
        color = _edge_color(port, session.covert, is_tor, is_mal)

        G.add_node(src_label, kind=src_kind, ip=src_ip)
        G.add_node(dst_label, kind=dst_kind, ip=dst_ip)

        # Collapse parallel edges — keep the most notable protocol color
        if G.has_edge(src_label, dst_label):
            prev_color = G[src_label][dst_label].get("color", "#607d8b")
            if _EDGE_PRIORITY.get(color, 0) > _EDGE_PRIORITY.get(prev_color, 0):
                G[src_label][dst_label]["color"] = color
                G[src_label][dst_label]["port"] = port
        else:
            G.add_edge(src_label, dst_label, color=color, port=port)

    if not G.nodes:
        log.info("Interactive graph: graph is empty after filtering")
        return

    # ── Layout — same engine selection as plot_lan_network.py ─────────────────
    n_lan = len(memory.lan_hosts)
    prog = "sfdp" if n_lan > 40 else "circo" if n_lan > 20 else "dot"
    try:
        pos = nx.nx_pydot.graphviz_layout(G, prog=prog)
    except Exception as exc:
        log.warning("graphviz_layout failed (%s), falling back to spring_layout", exc)
        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

    # ── Node colours ──────────────────────────────────────────────────────────
    mal_srcs  = {s.split("/")[0] for s in memory.possible_mal_traffic}
    mal_dsts  = {s.split("/")[1] for s in memory.possible_mal_traffic}
    tor_dsts  = {s.split("/")[1] for s in memory.possible_tor_traffic}

    node_colors = []
    for node in G.nodes:
        ip = G.nodes[node].get("ip", "")
        kind = G.nodes[node].get("kind", "")
        if ip in tor_dsts:
            node_colors.append("#9c27b0")   # purple — Tor destination
        elif ip in mal_srcs or ip in mal_dsts:
            node_colors.append("#f44336")   # red — malicious
        elif kind == "lan":
            node_colors.append("#1e88e5")   # blue — LAN host
        elif kind == "gw":
            node_colors.append("#78909c")   # gray — gateway/router
        else:
            node_colors.append("#ff7043")   # orange — unknown external

    edge_colors = [G[u][v].get("color", "#607d8b") for u, v in G.edges]
    edge_labels = {(u, v): _port_label(G[u][v].get("port", ""))
                   for u, v in G.edges}

    # ── Matplotlib figure ─────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor("#1e1e2e")
    ax.set_facecolor("#1e1e2e")

    nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                           node_size=700, alpha=0.92, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=6,
                            font_color="white", ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors,
                           arrows=True, arrowsize=14,
                           connectionstyle="arc3,rad=0.08", ax=ax, alpha=0.8)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels,
                                 font_size=5, font_color="#b0bec5", ax=ax)

    _add_legend(ax)
    ax.axis("off")
    fig.tight_layout(pad=0.5)

    # ── Embed to the right of ThirdFrame in base (column=11, row=40) ─────────
    _original_geometry = base.geometry()
    base.resizable(True, True)

    _container = tk.Frame(base, bg="#1e1e2e")
    _container.grid(row=40, column=11, sticky="nsew", padx=(6, 6), pady=(0, 6))

    toolbar_row = tk.Frame(_container, bg="#2e2e3e")
    toolbar_row.pack(side=tk.TOP, fill=tk.X)

    canvas_widget = FigureCanvasTkAgg(fig, master=_container)
    nav = NavigationToolbar2Tk(canvas_widget, toolbar_row, pack_toolbar=False)
    nav.update()
    nav.pack(side=tk.LEFT)
    ttk.Button(toolbar_row, text="Close", command=_close).pack(side=tk.RIGHT, padx=4, pady=2)

    canvas_widget.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    info_var = tk.StringVar(value="Click a node for details  |  "
                                  "Blue=LAN  Gray=Gateway  Red=Malicious  Purple=Tor")
    ttk.Label(_container, textvariable=info_var,
              anchor="w", padding=(6, 3)).pack(side=tk.BOTTOM, fill=tk.X)

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
        info_var.set(
            f"Node: {closest}  |  IP: {ip}  |  Domain: {domain}  |  Sessions: {len(sessions)}"
        )

    fig.canvas.mpl_connect("button_press_event", _on_click)
    _figure = fig


def _mac_label(mac: str) -> str:
    """Node label for a LAN host — mirrors plot_lan_network._node_label()."""
    h = memory.lan_hosts[mac]
    if h.node:
        return h.node
    return h.ip


def _edge_color(port: str, covert: bool, is_tor: bool, is_mal: bool) -> str:
    if is_mal:
        return "#f44336"
    if is_tor:
        return "#9c27b0"
    if covert:
        return "#00bcd4"
    if port == "443":
        return "#1e88e5"
    if port == "80":
        return "#43a047"
    if port == "53":
        return "#fdd835"
    if port == "1":      # ICMP type 1 / echo
        return "#ff7043"
    return "#607d8b"


def _port_label(port: str) -> str:
    return {"443": "HTTPS", "80": "HTTP", "53": "DNS"}.get(port, port)


def _add_legend(ax) -> None:
    import matplotlib.patches as mpatches
    legend_items = [
        mpatches.Patch(color="#1e88e5", label="LAN host"),
        mpatches.Patch(color="#78909c", label="Gateway"),
        mpatches.Patch(color="#f44336", label="Malicious"),
        mpatches.Patch(color="#9c27b0", label="Tor"),
    ]
    ax.legend(handles=legend_items, loc="upper left",
              facecolor="#2e2e3e", edgecolor="#555", labelcolor="white",
              fontsize=7)


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
        _b.after(50, lambda: (_b.geometry(_geom), _b.resizable(False, False)))
    _base = None
    _original_geometry = None
