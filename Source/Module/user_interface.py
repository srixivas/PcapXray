import sys
import os
import time
import logging
import threading
import webbrowser

from tkinter import *

log = logging.getLogger(__name__)
from tkinter import ttk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import queue as q

import tkinter as tk

import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import tor_traffic_handle
import sqlite_store
import memory
from PIL import Image, ImageTk

_SPIN_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_SPIN_COLOR  = "#4fc3f7"   # cyan — active
_DONE_COLOR  = "#81c784"   # green — success
_ERR_COLOR   = "#e57373"   # red   — error


class pcapXrayGui:
    def __init__(self, base):

        # TODO: is this req? Start getting tor consensus in the background
        #threading.Thread(target=tor_traffic_handle.TorTrafficHandle().get_consensus_data(), args=()).start()

        # Base Frame Configuration
        self.base = base
        base.title("PcapXray")
        Label(base, text="PcapXray Tool - A LAN Network Analyzer")

        # Style Configuration
        style = ttk.Style()
        style.configure("BW.TLabel", foreground="black")
        style.configure("BW.TEntry", foreground="black")

        # 1st Frame - Initial Frame
        InitFrame = ttk.Frame(base,  width=50, padding="10 0 0 0",relief= GROOVE)
        InitFrame.grid(column=10, row=10, sticky=(N, W, E, S))
        InitFrame.columnconfigure(4, weight=1)
        InitFrame.rowconfigure(0, weight=1)

        # Pcap File Entry
        self.pcap_file = StringVar()
        self.filename = ""
        ttk.Label(InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.filename_field = ttk.Entry(InitFrame, width=32, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        ttk.Button(InitFrame, text="Browse", command=lambda: self.browse_directory("pcap")).grid(column=2, row=0, padx=10, pady=10, sticky="E")
        self.analyze_button = ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse)
        self.analyze_button.grid(column=3, row=0, padx=10, pady=10, sticky="E")
        self._spin_label = tk.Label(InitFrame, text="", fg=_SPIN_COLOR,
                                    font=("Courier", 10), width=26, anchor="w")
        self._spin_label.grid(column=4, row=0, padx=10, pady=10, sticky="EW")
        self._spin_job: str | None = None
        self._spin_idx = 0
        self._spin_msg = ""

        # First Frame with Report Directory
        # Output and Results Frame
        FirstFrame = ttk.Frame(base,  width=50, padding="10 0 0 0", relief= GROOVE)
        FirstFrame.grid(column=10, row=20, sticky=(N, W, E, S))
        FirstFrame.columnconfigure(10, weight=1)
        FirstFrame.rowconfigure(20, weight=1)
        self.destination_report = StringVar(value=sys.path[0])
        ttk.Label(FirstFrame, text="Output directory path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.report_field = ttk.Entry(FirstFrame, width=30, textvariable=self.destination_report, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        
        # Browse button
        ttk.Button(FirstFrame, text="Browse", command=lambda: self.browse_directory("report")).grid(column=2, row=0, padx=10, pady=10,sticky="E")     

        # Pcap Engine selector
        self.engine = StringVar(value="auto")
        ttk.OptionMenu(FirstFrame, self.engine, "auto", "auto", "dpkt", "scapy", "pyshark").grid(
            row=0, column=3, padx=5, sticky="W"
        )

        # Zoom 
        self.zoom = [900,500]
        ttk.Button(FirstFrame, text="zoomIn", command=self.zoom_in).grid(row=0,column=10, padx=5, sticky="E")
        ttk.Button(FirstFrame, text="zoomOut", command=self.zoom_out).grid(row=0,column=19,padx=10, sticky="E")   

        # Second Frame with Options
        SecondFrame = ttk.Frame(base,  width=50, padding="10 10 10 10",relief= GROOVE)
        SecondFrame.grid(column=10, row=30, sticky=(N, W, E, S))
        SecondFrame.columnconfigure(10, weight=1)
        SecondFrame.rowconfigure(30, weight=1)
        ttk.Label(SecondFrame, text="Traffic: ", style="BW.TLabel").grid(row=10,column=0,sticky="W")
        self.option = StringVar()
        self.options = {'All', 'HTTP', 'HTTPS', 'Tor', 'Malicious', 'ICMP', 'DNS'}
        #self.option.set('Tor')
        ttk.OptionMenu(SecondFrame,self.option,"Select",*self.options).grid(row=10,column=1, padx=10, sticky="W")
        self.ibutton = ttk.Button(SecondFrame, text="Graph Panel", command=self.gimmick)
        self.ibutton.grid(row=10, column=10, padx=10, sticky="E")
        self.trigger = ttk.Button(SecondFrame, text="Visualize!", command=self.map_select)
        self.trigger.grid(row=10,column=11, sticky="E")
        self.browser_button = ttk.Button(SecondFrame, text="Interactive Graph", command=self.open_in_browser)
        self.browser_button.grid(row=10, column=12, padx=10, sticky="E")
        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'

        self.img = ""
        self._store = sqlite_store.SqliteStore()
        
        ## Filters
        self.from_ip = StringVar()
        self.from_hosts = ["All"]
        self.to_ip = StringVar()
        self.to_hosts = ["All"]
        ttk.Label(SecondFrame, text="From: ", style="BW.TLabel").grid(row=10, column=2, sticky="W")
        self.from_menu = ttk.Combobox(SecondFrame, width=15, textvariable=self.from_ip, values=self.from_hosts)
        self.from_menu.grid(row=10, column=3, padx=10, sticky="E")
        ttk.Label(SecondFrame, text="To: ", style="BW.TLabel").grid(row=10, column=4, sticky="W")
        self.to_menu = ttk.Combobox(SecondFrame, width=15, textvariable=self.to_ip, values=self.to_hosts)
        self.to_menu.grid(row=10, column=5, padx=10, sticky="E")

        # Default filter values
        self.from_menu.set("All")
        self.to_menu.set("All")
        self.option.set("All")

        # Third Frame with Results and Descriptioms
        self.ThirdFrame = ttk.Frame(base,  width=100, height=100, padding="10 10 10 10",relief= GROOVE)
        description = """It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.\nThis prototype aims to accomplish 4 important modules,
                        \n 1. Web Traffic\n 2. Tor Traffic \n 3. Malicious Traffic \n 4. Device/Traffic Details \n 5. Covert Communication \n \nPlease contact me @ spg349@nyu.edu for any bugs or problems !
                      """
        self.label = ttk.Label(self.ThirdFrame, text="Description: \nPcapXray tools is an aid for Network Forensics or Any Network Analysis!\n"+description, style="BW.TLabel")
        self.label.grid(column=10, row=10,sticky="W")
        self.xscrollbar = Scrollbar(self.ThirdFrame, orient=HORIZONTAL)
        self.xscrollbar.grid(row=100, column=0, sticky=E + W)
        self.yscrollbar = Scrollbar(self.ThirdFrame, orient=VERTICAL)
        self.yscrollbar.grid(row=0, column=100, sticky=N + S)
        self.ThirdFrame.grid(column=10, row=40, sticky=(N, W, E, S))
        self.ThirdFrame.columnconfigure(0, weight=1)
        self.ThirdFrame.rowconfigure(0, weight=1)

        base.resizable(False, False)
        base.rowconfigure(40, weight=1)
        base.columnconfigure(10, weight=1)

    def browse_directory(self, option):
        if option == "pcap":
            self.pcap_file.set(fd.askopenfilename(initialdir=sys.path[0], title="Select Packet Capture File!", filetypes=(("All", "*.pcap *.pcapng"), ("pcap files", "*.pcap"), ("pcapng files", "*.pcapng"))))
            self.filename = self.pcap_file.get().replace(".pcap", "").replace(".pcapng", "")
            if "/" in self.filename:
                self.filename = self.filename.split("/")[-1]
        else:
            self.destination_report.set(fd.askdirectory())
            if self.destination_report.get():
                if not os.access(self.destination_report.get(), os.W_OK):
                    mb.showerror("Error", "Permission denied to create report! Run with higher privilege.")
            else:
                mb.showerror("Error", "Enter a output directory!")
        # Restore focus to main window after any native dialog (macOS loses focus otherwise)
        self.base.lift()
        self.base.focus_force()
    
    """
    def update_ips(self, direction):
        if direction == "to":
            self.to_hosts += list(memory.destination_hosts.keys())
            self.to_menu['values'] = self.to_hosts
        else:
            for mac in memory.lan_hosts:
                self.to_hosts += memory.lan_hosts[mac].ip
                self.from_hosts += memory.lan_hosts[mac].ip
            self.from_menu['values'] = self.from_hosts
    """

    # ------------------------------------------------------------------
    # Spinner helpers
    # ------------------------------------------------------------------

    def _spin_start(self, text: str = "Working") -> None:
        self._spin_msg = text
        self._spin_idx = 0
        self._spin_label.config(fg=_SPIN_COLOR)
        self._spin_tick()

    def _spin_tick(self) -> None:
        frame = _SPIN_FRAMES[self._spin_idx % len(_SPIN_FRAMES)]
        self._spin_label.config(text=f"{frame} {self._spin_msg}")
        self._spin_idx += 1
        self._spin_job = self.base.after(80, self._spin_tick)

    def _spin_stop(self, done_text: str = "", ok: bool = True) -> None:
        if self._spin_job is not None:
            self.base.after_cancel(self._spin_job)
            self._spin_job = None
        self._spin_label.config(fg=_DONE_COLOR if ok else _ERR_COLOR,
                                text=done_text)

    def _run_in_thread(self, fn, *args) -> tuple[threading.Thread, list]:
        """Run fn(*args) in a daemon thread; store any exception in exc_box[0]."""
        exc_box: list = []
        def wrapper():
            try:
                fn(*args)
            except Exception as e:
                exc_box.append(e)
        t = threading.Thread(target=wrapper, daemon=True)
        t.start()
        return t, exc_box

    def _poll_thread(self, thread: threading.Thread) -> None:
        """Block the caller while driving the Tk event loop until thread finishes."""
        while thread.is_alive():
            self.base.update()
            thread.join(timeout=0.05)

    def pcap_analyse(self):
        if not os.access(self.destination_report.get(), os.W_OK):
            mb.showerror("Error", "Permission denied to create report! Run with higher privilege.")
            return

        log.info("pcap_analyse: file=%s", self.pcap_file.get())
        if not os.path.exists(self.pcap_file.get()):
            mb.showerror("Error", "File Not Found!")
            return

        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'
        self.to_menu['state'] = 'disabled'
        self.from_menu['state'] = 'disabled'
        self.analyze_button['state'] = 'disabled'

        # Derive filename if user typed the path directly instead of using Browse
        if not self.filename:
            self.filename = os.path.basename(self.pcap_file.get()).replace(".pcap", "").replace(".pcapng", "")

        # Offer to reload from SQLite cache if this PCAP was analyzed before
        if self.filename and self._store.has_session(self.filename):
            if mb.askyesno("Reload Session",
                           f"Cached analysis found for '{self.filename}'.\n"
                           "Reload without re-parsing the PCAP?"):
                log.info("pcap_analyse: reloading session '%s' from cache", self.filename)
                self._spin_start("Loading cache")
                self._store.load_session(self.filename)
                self._spin_stop(f"✓ {len(memory.packet_db)} sessions (cached)")
                self._populate_filter_menus()
                self._re_enable_controls()
                return

        self._spin_start("Reading packets")
        packet_read, exc_box = self._run_in_thread(pcap_reader.PcapEngine, self.pcap_file.get(), self.engine.get())
        self._poll_thread(packet_read)

        if exc_box:
            self._spin_stop("✗ Analysis failed", ok=False)
            log.error("PCAP analysis failed: %s", exc_box[0])
            mb.showerror("Analysis Error", f"PCAP analysis failed:\n{exc_box[0]}")
            self._re_enable_controls()
            return

        self._spin_stop(f"✓ {len(memory.packet_db)} sessions")

        log.info("pcap_analyse: read complete, generating packet report")
        threading.Thread(target=report_generator.ReportGenerator(self.destination_report.get(), self.filename).packetDetails, args=(), daemon=True).start()

        if self.filename:
            self._store.save_session(self.filename)
        self._populate_filter_menus()
        self._re_enable_controls()

    def _populate_filter_menus(self) -> None:
        self.details_fetch = 0
        self.to_hosts = ["All"]
        self.from_hosts = ["All"]
        self.from_menu.set("All")
        self.to_menu.set("All")
        self.option.set("All")
        self.to_hosts += list(memory.destination_hosts.keys())
        for mac in list(memory.lan_hosts.keys()):
            self.base.update()
            self.from_hosts.append(memory.lan_hosts[mac].ip)
        self.to_hosts = list(set(self.to_hosts + self.from_hosts))
        self.to_menu['values'] = self.to_hosts
        self.from_menu['values'] = self.from_hosts

    def _re_enable_controls(self) -> None:
        self.trigger['state'] = 'normal'
        self.ibutton['state'] = 'normal'
        self.browser_button['state'] = 'normal'
        self.to_menu['state'] = 'normal'
        self.from_menu['state'] = 'normal'
        self.analyze_button['state'] = 'normal'

    def generate_graph(self):
        log.info("generate_graph: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        if self.details_fetch == 0:
            t, _ = self._run_in_thread(communication_details_fetch.TrafficDetailsFetch, "sock")
            t1, _ = self._run_in_thread(device_details_fetch.FetchDeviceDetails("ieee").fetch_info)
            self._spin_start("Resolving hosts")
            self._poll_thread(t)
            self._poll_thread(t1)
            self._spin_stop("✓ Hosts resolved")

            self.details_fetch = 1
            rpt = report_generator.ReportGenerator(self.destination_report.get(), self.filename)
            threading.Thread(target=rpt.communicationDetailsReport, daemon=True).start()
            threading.Thread(target=rpt.deviceDetailsReport, daemon=True).start()

        options = self.option.get() + "_" + self.to_ip.get().replace(".", "-") + "_" + self.from_ip.get().replace(".", "-")
        self.image_file = os.path.join(self.destination_report.get(), "Report", self.filename + "_" + options + ".png")
        if not os.path.exists(self.image_file):
            t1, exc_box = self._run_in_thread(plot_lan_network.PlotLan, self.filename, self.destination_report.get(), self.option.get(), self.to_ip.get(), self.from_ip.get())
            self._spin_start("Rendering graph")
            self._poll_thread(t1)
            if exc_box:
                self._spin_stop("✗ Render failed", ok=False)
                log.error("Graph generation failed: %s", exc_box[0])
                mb.showerror("Graph Error", f"Graph generation failed:\n{exc_box[0]}")
                return
            self._spin_stop("✓ Graph ready")
            self.label.grid_forget()
            self.load_image()
        else:
            self.label.grid_forget()
            self.load_image()
        self.ibutton['state'] = 'normal'

    def gimmick(self):
        import interactive_gui
        interactive_gui.gimmick_initialize(self.base, "file://" + self.image_file.replace(".png", ".html"))

    def open_in_browser(self):
        html_path = self.image_file.replace(".png", ".html")
        if os.path.exists(html_path):
            webbrowser.open("file://" + html_path)
        else:
            mb.showerror("Error", "Interactive HTML not found. Click Visualize! first.")

    def load_image(self):
        if not hasattr(self, '_canvas_w'):
            # Expand to graph-viewing size on first load, then lock.
            self.base.resizable(True, True)
            self.base.geometry("1100x780")
            probe = Canvas(self.ThirdFrame, bd=0)
            probe.grid(column=0, row=0, sticky=(N, W, E, S))
            self.base.update_idletasks()
            self._canvas_w = probe.winfo_width() or 900
            self._canvas_h = probe.winfo_height() or 500
            self.zoom = [self._canvas_w, self._canvas_h]
            probe.destroy()
            self.base.resizable(False, False)

        self.canvas = Canvas(self.ThirdFrame, width=self._canvas_w, height=self._canvas_h,
                             bd=0, bg="navy",
                             xscrollcommand=self.xscrollbar.set,
                             yscrollcommand=self.yscrollbar.set)
        self.canvas.grid(column=0, row=0, sticky=(N, W, E, S))
        self.img = ImageTk.PhotoImage(Image.open(self.image_file).resize(tuple(self.zoom), Image.LANCZOS))
        self.canvas.create_image(0, 0, image=self.img, anchor=NW)
        self.canvas.config(scrollregion=self.canvas.bbox(ALL))
        self.xscrollbar.config(command=self.canvas.xview)
        self.yscrollbar.config(command=self.canvas.yview)

    def map_select(self, *args):
        log.debug("map_select: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        self.trigger['state'] = 'disabled'
        self.analyze_button['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.browser_button['state'] = 'disabled'
        self.generate_graph()
        self.trigger['state'] = 'normal'
        self.ibutton['state'] = 'normal'
        self.browser_button['state'] = 'normal'
        self.analyze_button['state'] = 'normal'

    def zoom_in(self):
        log.debug("zoom_in")
        self.zoom[0] += 100
        self.zoom[1] += 100
        if self.img:
             self.load_image()

    def zoom_out(self):
        log.debug("zoom_out")
        min_w = getattr(self, '_canvas_w', 900)
        min_h = getattr(self, '_canvas_h', 500)
        if self.zoom[0] > min_w and self.zoom[1] > min_h:
            self.zoom[0] -= 100
            self.zoom[1] -= 100
        else:
            log.debug("zoom_out: already at minimum size")
        if self.img:
             self.load_image()

class OtherFrame(Toplevel):

    def __init__(self, x, y):
        """Constructor"""
        Toplevel.__init__(self)
        self.geometry("+%d+%d" % (x + 100, y + 200))
        self.title("otherFrame")

def main():
    base = Tk()
    pcapXrayGui(base)
    # macOS: grab focus after the window fully renders (avoids needing to
    # click the title bar before buttons respond)
    base.after(200, lambda: (base.lift(), base.focus_force()))
    base.mainloop()

