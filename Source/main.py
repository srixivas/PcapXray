# Main File - Driver for the Application PcapXray

# Import Libraries
import os   #-- default lib - packed with python
import sys  #-- default lib
import datetime  #-- default lib

if sys.platform == 'darwin':
    import matplotlib
    matplotlib.use('TkAgg')

interactive_graph_support = False
try:
    from cefpython3 import cefpython as cef
    interactive_graph_support = True
except Exception:
    print("Interactive graph in app wont work as python version/platform is not supported (will launch in default browser)")
    pass

try:
    # for Python2
    from Tkinter import *
    import ttk
except ImportError:
    # for Python3
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

