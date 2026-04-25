import sys
import os
import time
import logging
import threading

from tkinter import *

log = logging.getLogger(__name__)
from tkinter import ttk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
import queue as q

import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import tor_traffic_handle
import memory
from PIL import Image, ImageTk

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
        InitFrame.columnconfigure(10, weight=1)
        InitFrame.rowconfigure(10, weight=1)

        # Pcap File Entry
        self.pcap_file = StringVar()
        self.filename = ""
        ttk.Label(InitFrame, text="Enter pcap file path: ",style="BW.TLabel").grid(column=0, row=0, sticky="W")
        self.filename_field = ttk.Entry(InitFrame, width=32, textvariable=self.pcap_file, style="BW.TEntry").grid(column=1, row=0, sticky="W, E")
        self.progressbar = ttk.Progressbar(InitFrame, orient="horizontal", length=200,value=0, maximum=200,  mode="indeterminate")
        # Browse button
        #self.filename = StringVar()
        ttk.Button(InitFrame, text="Browse", command=lambda: self.browse_directory("pcap")).grid(column=2, row=0, padx=10, pady=10,sticky="E")
        self.analyze_button = ttk.Button(InitFrame, text="Analyze!", command=self.pcap_analyse)
        self.analyze_button.grid(column=3, row=0, padx=10, pady=10,sticky="E")
        self.progressbar.grid(column=4, row=0, padx=10, pady=10, sticky="E")

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

        # Pcap Engine
        # * Add Pcap Engine with an Engine Selection here once tested with full support
        # * Need to solve pyshark errors: main thread event loop, infinite loop in file capture
        self.engine = StringVar()
        #self.engines = { 'scapy', 'pyshark' }
        #ttk.OptionMenu(FirstFrame, self.engine, "Engine", *self.engines).grid(row=0,column=3, padx=5, sticky="W")
        self.engine.set('scapy')

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
        self.ibutton = ttk.Button(SecondFrame, text="InteractiveMagic!", command=self.gimmick)
        self.ibutton.grid(row=10, column=10, padx=10, sticky="E")
        self.trigger = ttk.Button(SecondFrame, text="Visualize!", command=self.map_select)
        self.trigger.grid(row=10,column=11, sticky="E")
        self.trigger['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'

        self.img = ""
        
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
        self.ThirdFrame.columnconfigure(10, weight=1)
        self.ThirdFrame.rowconfigure(40, weight=1)

        base.resizable(False, False) 
        base.rowconfigure(0, weight=1)
        base.columnconfigure(0, weight=1)

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
        if os.path.exists(self.pcap_file.get()):

            self.trigger['state'] = 'disabled'
            self.ibutton['state'] = 'disabled'
            self.to_menu['state'] = 'disabled'
            self.from_menu['state'] = 'disabled'
            self.analyze_button['state'] = 'disabled'

            self.progressbar.start()

            packet_read, exc_box = self._run_in_thread(pcap_reader.PcapEngine, self.pcap_file.get(), self.engine.get())
            self._poll_thread(packet_read)
            self.progressbar.stop()

            if exc_box:
                log.error("PCAP analysis failed: %s", exc_box[0])
                mb.showerror("Analysis Error", f"PCAP analysis failed:\n{exc_box[0]}")
                self._re_enable_controls()
                return

            log.info("pcap_analyse: read complete, generating packet report")
            threading.Thread(target=report_generator.ReportGenerator(self.destination_report.get(), self.filename).packetDetails, args=(), daemon=True).start()

            self.details_fetch = 0
            self.to_hosts = ["All"]
            self.from_hosts = ["All"]
            self.from_menu.set("All")
            self.to_menu.set("All")
            self.option.set("All")

            self.progressbar.start()
            self.to_hosts += list(memory.destination_hosts.keys())
            for mac in list(memory.lan_hosts.keys()):
                self.base.update()
                self.from_hosts.append(memory.lan_hosts[mac].ip)
            self.to_hosts = list(set(self.to_hosts + self.from_hosts))
            self.to_menu['values'] = self.to_hosts
            self.from_menu['values'] = self.from_hosts
            self.progressbar.stop()

            self._re_enable_controls()
        else:
            mb.showerror("Error", "File Not Found !")

    def _re_enable_controls(self) -> None:
        self.trigger['state'] = 'normal'
        self.ibutton['state'] = 'normal'
        self.to_menu['state'] = 'normal'
        self.from_menu['state'] = 'normal'
        self.analyze_button['state'] = 'normal'

    def generate_graph(self):
        log.info("generate_graph: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        if self.details_fetch == 0:
            t, _ = self._run_in_thread(communication_details_fetch.TrafficDetailsFetch, "sock")
            t1, _ = self._run_in_thread(device_details_fetch.FetchDeviceDetails("ieee").fetch_info)
            self.progressbar.start()
            self._poll_thread(t)
            self._poll_thread(t1)
            self.progressbar.stop()

            self.details_fetch = 1
            rpt = report_generator.ReportGenerator(self.destination_report.get(), self.filename)
            threading.Thread(target=rpt.communicationDetailsReport, daemon=True).start()
            threading.Thread(target=rpt.deviceDetailsReport, daemon=True).start()

        options = self.option.get() + "_" + self.to_ip.get().replace(".", "-") + "_" + self.from_ip.get().replace(".", "-")
        self.image_file = os.path.join(self.destination_report.get(), "Report", self.filename + "_" + options + ".png")
        if not os.path.exists(self.image_file):
            t1, exc_box = self._run_in_thread(plot_lan_network.PlotLan, self.filename, self.destination_report.get(), self.option.get(), self.to_ip.get(), self.from_ip.get())
            self.progressbar.start()
            self._poll_thread(t1)
            self.progressbar.stop()
            if exc_box:
                log.error("Graph generation failed: %s", exc_box[0])
                mb.showerror("Graph Error", f"Graph generation failed:\n{exc_box[0]}")
                return
            self.label.grid_forget()
            self.load_image()
        else:
            self.label.grid_forget()
            self.load_image()
        self.ibutton['state'] = 'normal'

    def gimmick(self):
        import interactive_gui
        interactive_gui.gimmick_initialize(self.base, "file://"+self.image_file.replace(".png",".html"))

    def load_image(self):
        self.canvas = Canvas(self.ThirdFrame, width=900,height=500, bd=0, bg="navy", xscrollcommand=self.xscrollbar.set, yscrollcommand=self.yscrollbar.set)
        #self.canvas.grid(row=0, column=0, sticky=N + S + E + W)
        self.canvas.grid(column=0, row=0, sticky=(N, W, E, S))
        #self.canvas.pack(side = RIGHT, fill = BOTH, expand = True)
        self.img = ImageTk.PhotoImage(Image.open(self.image_file).resize(tuple(self.zoom), Image.LANCZOS))#.convert('RGB'))
        self.canvas.create_image(0,0, image=self.img)
        self.canvas.config(scrollregion=self.canvas.bbox(ALL))
        self.xscrollbar.config(command=self.canvas.xview)
        self.yscrollbar.config(command=self.canvas.yview)
        #self.canvas.rowconfigure(0, weight=1)
        #self.canvas.columnconfigure(0, weight=1)

    def map_select(self, *args):
        log.debug("map_select: option=%s to=%s from=%s", self.option.get(), self.to_ip.get(), self.from_ip.get())
        self.trigger['state'] = 'disabled'
        self.analyze_button['state'] = 'disabled'
        self.ibutton['state'] = 'disabled'
        self.generate_graph()
        self.trigger['state'] = 'normal'
        self.ibutton['state'] = 'normal'
        self.analyze_button['state'] = 'normal'

    def zoom_in(self):
        log.debug("zoom_in")
        self.zoom[0] += 100
        self.zoom[1] += 100
        if self.img:
             self.load_image()

    def zoom_out(self):
        log.debug("zoom_out")
        if self.zoom[0] > 900 and self.zoom[1] > 500:
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
    base.mainloop()

