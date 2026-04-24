# Main File - Driver for the Application PcapXray
import os
import sys
import logging

_log_file = os.path.join(os.path.expanduser("~"), "PcapXray.log")
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("PCAPXRAY_DEBUG") else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(_log_file, mode="w"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)
log.info("PcapXray starting — log file: %s", _log_file)

interactive_graph_support = False
try:
    from cefpython3 import cefpython as cef
    interactive_graph_support = True
except Exception:
    log.warning("cefpython3 unavailable — interactive graph will open in default browser")

from tkinter import *
from tkinter import ttk

# Import Custom Modules - Self created by the author
if sys.path[0]:
    sys.path.insert(0,sys.path[0]+'/Module/')
else:
    sys.path.insert(0, 'Module/')
import user_interface

# Import 3rd party Libraries -- Needed to be installed using pip
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def main():
    base = Tk()
    logo_file = os.path.join(os.path.dirname(__file__), 'Module/assets/logo.gif')
    icon = PhotoImage(file=logo_file)
    base.tk.call('wm','iconphoto',base._w,icon)
    user_interface.pcapXrayGui(base)
    if interactive_graph_support:
        cef.Initialize()
    base.mainloop()
    if interactive_graph_support:
        cef.Shutdown()

main()

