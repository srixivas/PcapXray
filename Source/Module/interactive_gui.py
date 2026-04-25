"""
Interactive network graph — embedded matplotlib+networkx canvas inside ThirdFrame.
Uses the same graphviz layout engine selection as plot_lan_network.py.
"""
import logging
import tkinter as tk
from tkinter import ttk

import memory

__all__ = ["gimmick_initialize"]

log = logging.getLogger(__name__)

_container: tk.Frame | None = None   # singleton container widget
_figure = None                         # keep matplotlib figure alive
_restore_fn = None                     # callback to restore PIL canvas on close


def gimmick_initialize(frame: tk.Frame, _html_path: str, restore_fn=None) -> None:
    """Embed (or close) the interactive graph inside *frame*.

    Called by user_interface.pcapXrayGui.gimmick().  The html_path arg is
    kept for API compatibility but is no longer used.  restore_fn, if given,
    is called when the user closes the interactive view so the caller can
    restore the PIL canvas.
    """
    global _container, _figure, _restore_fn

    # Toggle: second call closes the graph and restores the previous view.
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

    _restore_fn = restore_fn

    # ── Build networkx graph from memory ─────────────────────────────────────
    G = nx.DiGraph()
    edge_labels: dict[tuple, str] = {}

    lan_ips = {h.ip for h in memory.lan_hosts.values()}

    for session in memory.packet_db:
        parts = session.split("/")
        if len(parts) != 3:
            continue
        src_ip, dst_ip, port = parts

        src_label = _node_label(src_ip)
        dst_label = _node_label(dst_ip)

        is_covert = memory.packet_db[session].covert
        is_mal = session in memory.possible_mal_traffic
        is_tor = session in memory.possible_tor_traffic

        G.add_node(src_label, ip=src_ip,
                   kind="lan" if src_ip in lan_ips else "ext")
        G.add_node(dst_label, ip=dst_ip,
                   kind="lan" if dst_ip in lan_ips else "ext")
        G.add_edge(src_label, dst_label,
                   port=port, covert=is_covert, mal=is_mal, tor=is_tor)
        edge_labels[(src_label, dst_label)] = port

    # ── Node colours ──────────────────────────────────────────────────────────
    mal_ips = {s.split("/")[1] for s in memory.possible_mal_traffic}
    tor_ips = {s.split("/")[1] for s in memory.possible_tor_traffic}

    node_colors = []
    for node in G.nodes:
        ip = G.nodes[node].get("ip", "")
        if ip in tor_ips:
            node_colors.append("#9c27b0")   # purple — Tor
        elif ip in mal_ips:
            node_colors.append("#f44336")   # red — malicious
        elif G.nodes[node].get("kind") == "lan":
            node_colors.append("#1e88e5")   # blue — LAN host
        else:
            node_colors.append("#ff7043")   # orange — external

    # ── Layout — mirrors plot_lan_network.py engine selection ─────────────────
    n_lan = len(memory.lan_hosts)
    if n_lan > 40:
        prog = "sfdp"
    elif n_lan > 20:
        prog = "circo"
    else:
        prog = "dot"

    try:
        pos = nx.nx_pydot.graphviz_layout(G, prog=prog)
    except Exception as exc:
        log.warning("graphviz_layout failed (%s), falling back to spring_layout", exc)
        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

    # ── Matplotlib figure ─────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(11, 7))
    fig.patch.set_facecolor("#1e1e2e")
    ax.set_facecolor("#1e1e2e")

    nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                           node_size=600, alpha=0.92, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=6,
                            font_color="white", ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color="#607d8b",
                           arrows=True, arrowsize=12,
                           connectionstyle="arc3,rad=0.1", ax=ax, alpha=0.7)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels,
                                 font_size=5, font_color="#b0bec5", ax=ax)

    _add_legend(ax)
    ax.axis("off")
    fig.tight_layout()

    # ── Embed inside the passed frame ─────────────────────────────────────────
    _container = tk.Frame(frame, bg="#1e1e2e")
    _container.grid(row=0, column=0, sticky="nsew", columnspan=90)
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    # Top toolbar row: matplotlib navigation + close button
    toolbar_row = tk.Frame(_container, bg="#2e2e3e")
    toolbar_row.pack(side=tk.TOP, fill=tk.X)

    canvas_widget = FigureCanvasTkAgg(fig, master=_container)
    nav = NavigationToolbar2Tk(canvas_widget, toolbar_row, pack_toolbar=False)
    nav.update()
    nav.pack(side=tk.LEFT)

    ttk.Button(toolbar_row, text="Close", command=_close).pack(side=tk.RIGHT, padx=4, pady=2)

    canvas_widget.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Info bar at bottom — updated on node click
    info_var = tk.StringVar(value="Click a node for session details  |  "
                                  "Blue=LAN  Orange=External  Red=Malicious  Purple=Tor")
    ttk.Label(_container, textvariable=info_var,
              anchor="w", padding=(8, 4)).pack(side=tk.BOTTOM, fill=tk.X)

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
        if closest is None or min_dist > 0.1:
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


def _add_legend(ax) -> None:
    import matplotlib.patches as mpatches
    legend_items = [
        mpatches.Patch(color="#1e88e5", label="LAN host"),
        mpatches.Patch(color="#ff7043", label="External"),
        mpatches.Patch(color="#f44336", label="Malicious"),
        mpatches.Patch(color="#9c27b0", label="Tor"),
    ]
    ax.legend(handles=legend_items, loc="upper left",
              facecolor="#2e2e3e", edgecolor="#555", labelcolor="white",
              fontsize=7)


def _node_label(ip: str) -> str:
    for host in memory.lan_hosts.values():
        if host.ip == ip:
            return host.node if host.node else ip
    if ip in memory.destination_hosts:
        h = memory.destination_hosts[ip]
        if h.domain_name and h.domain_name not in ("NotResolvable", ""):
            return h.domain_name
    return ip


def _close() -> None:
    global _container, _figure, _restore_fn
    import matplotlib.pyplot as plt
    if _figure is not None:
        plt.close(_figure)
        _figure = None
    if _container is not None and _container.winfo_exists():
        _container.destroy()
        _container = None
    if _restore_fn is not None:
        _restore_fn()
        _restore_fn = None
