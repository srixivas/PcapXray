# PcapXray [![CI](https://github.com/srixivas/PcapXray/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/srixivas/PcapXray/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/srixivas/PcapXray/branch/master/graph/badge.svg)](https://codecov.io/gh/srixivas/PcapXray) [![defcon27](https://img.shields.io/badge/defcon27-demolabs-blue)](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html#PcapXray)
    A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction
![PcapXray](logo.png "PcapXray")
## PcapXray Design Specification
Wiki has more help too.

### Goal:
  Given a Pcap File, plot a network diagram displaying hosts in the network, network traffic, highlight important traffic and Tor traffic as well as potential malicious traffic including data involved in the communication.

### Problem:
* Investigation of a Pcap file takes a long time given initial glitch to start the investigation
*	Faced by every forensics investigator and anyone who is analyzing the network

* Location: https://github.com/srixivas/PcapXray

### Solution: Speed up the investigation process
* Make a network diagram with the following features from a Pcap file
Tool Highlights:
* Network Diagram – Summary Network Diagram of full network
* Information: 
  * Web Traffic with Server Details
  * Tor Traffic
  * Possible Malicious traffic
  * Data Obtained from Packet in Report – Device/Traffic/Payloads
  * Device Details
  
### Tool Image:
![Screen 1](Samples/screen2_6_1.png)

![Screen 2](Samples/screen2_6_2.png)

### Components:
* Network Diagram 
* Device/Traffic Details and Analysis
* Malicious Traffic Identification
* Tor Traffic
* GUI – a gui with options to upload pcap file and display the network diagram

### Setup 

* Python 3

```bash
apt install python3-pip
apt install python3-tk
apt install graphviz
apt install python3-pil python3-pil.imagetk
pip3 install -r requirements.txt
python3 Source/main.py
```
( Make sure to escalate privilege to allow file creations - Run with `sudo` )

For MAC:
```
brew install graphviz
```

* Python 2

```bash
apt install python-tk
apt install graphviz
pip install -r requirements.txt
python Source/main.py
```
( Make sure to escalate privilege to allow file creations - Run with `sudo` )

### Python Libraries Used:  - All these libraries are required for functionality
* Tkinter and TTK – Install from pip or apt-get – Ensure Tkinter and graphviz is installed (Most Linux contain by default) 
  * apt install python-tk
  * apt install graphviz
  * apt install python3-tk (for python3 support)
  * Sometimes ImageTk errors are thrown in python3 env --> use apt install python3-pil python3-pil.imagetk
* All these are included in the requirements.txt file
  * Scapy – rdpcap to read the packets from the pcap file 
  *	Ipwhois – to obtain whois information from ip
  *	Netaddr – to check ip information type
  *	Pillow – image processing library
  *	Stem – tor consensus data fetch library
  *	pyGraphviz – plot graph
  *	Networkx – plot graph
  *	Matplotlib – plot graph (not used as of now)
  
### Demo
![Demo](Samples/demo2_6.gif)

### Getting started:
* Clone the repository
* pip install -r requirements.txt
* python Source/main.py

### Additional Information:
* Tested on Linux
* Options for Traffic include - Web (HTTP and HTTPS), Tor, Malicious, ICMP, DNS
 
### Challenges:
  * Unstability of the TK GUI:
    * Decision on the GUI between Django and TK, settled upon tk for a simple local interface, but the unstability of the tk gui caused a number of problems
  * Graph Plotting:
    * Plotting a proper network graph which is readable from the data obtained was quite an effort, used different libraries to arrive at one.
  * Performance and Timing:
    * The performance and timing of the total application was a big challenge with different data gathering and output generation

### Known Bugs:
* Memory Hogging
  * Sometimes memory hogging occurs when lower RAM is present in the system as the data stored in the memory from the pcap file is huge
  * Should be Fixed by moving data into a database than the memory itself
* Race Condition
  * Due to mainloop of the TK gui, other threads could undergo a race condition
  * Should be fixed by moving to a better structured TK implementation or Web GUI
* Tk GUI Unstability:
  * Same reason as above
* Code:
  * clumsy and unstructured code flow

*	Current Fix in rare occasions: If any of the above issue occurs the progress bar keeps running and no output is generated, a restart of the app would be required.

### Docker Containers of PcapXray
* Dockerfile present in the root folder was used to build images
* Already built docker images are found at dockerhub
  - srinivas11789/pcapxray-1.0
  - srinivas11789/pcapxray-2.2
* Performing the steps in `run.sh` file manually would work to launch the tool via docker (I can help with errors)
* Running `run.sh` scripts is an attempt to automate (would not work 100 percent)
  - tested on mac and linux - will be better soon!...

### Immediate Future Tasks: (Target: 3.0)

- Clean up code (beautify code base from being a prototype)
- Report generation on unique folders for all assets of a packet capture
- Suspicious activity detection
- Support more pcap reader engine
- Traffic support: ICMP, DNS
- Known file type detection and Extract
- Python2 and Python3
- Interactive map

### Future:
* Structured and clean code flow
*	Change the database from JSON to sqlite or prominent database, due to memory hogging
*	Change fronend to web based such as Django
*	Make the application more stable
* More protocol support
* Clean up code

### Credits:
* Thanks for making it better,
  - Professor Marc Budofsky
  - Kevin Gallagher
* Thanks for all the dependent libraries used
* Logo created with logomakr.com and www.inkscape.org

## ***Just for Security Fun!***
