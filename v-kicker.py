import curses
import os
import signal
import subprocess
import sys
from threading import Thread
import time

# ---[ CLASSES ]--- #

class Adapter:
  def __init__(self, name, is_monitor):
    self.name = name
    self.is_monitor = is_monitor

class Network:
    def __init__(self, bssid, channel, power, essid):
        self.bssid = bssid
        self.channel = channel
        self.power = power
        self.essid = essid

# ---[ GLOBAL VARIABLES ]--- #

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

# List of Adapter objects
adapters = []

# Choosen adapter
choosen_adapter = None

# Network scan thread
thread_network_scan = None
cmd_network_scan = None

# Read networks thread
thread_read_networks = None

# List of Network objects
networks = []

# Choosen network
choosen_network = None

# ---[ MANAGEMENT ]--- #

def is_root():
    return os.geteuid() == 0

def show_error(msg):
    print("[x]: " + msg)

def show_msg(msg):
    print("[!]: " + msg)

def show_question(msg):
    return input("[?]: " + msg + " ")

def has_monitor_adapter():
    for adapter in adapters:
        if adapter.is_monitor:
            return adapter
    
    return None

def threaded_network_scan():
    global cmd_network_scan
    cmd_network_scan = subprocess.Popen("airodump-ng wlan0mon --write tmp_networks --update 1 --output-format csv --write-interval 1", shell = True)
    i = 0

def threaded_read_networks():
    while True:
        if os.path.exists(os.path.join(__location__, 'tmp_networks-01.csv')) == False:
            time.sleep(1)
            continue

        with open(os.path.join(__location__, 'tmp_networks-01.csv')) as file:
            lines = [line.rstrip() for line in file]
        
        i_start = -1
        i_end = -1

        for i, line in enumerate(lines):
            if "BSSID" in line and i_start == -1:
                i_start = i + 1
            
            if "Station MAC" in line and i_end == -1:
                i_end = i - 1

        if i_start < 0 or i_end < 0:
            show_error("Unable to parse the file")
            sys.exit(1)

        networks.clear()

        for raw_network in lines[i_start : i_end]:
            network = raw_network.split(",")

            bssid = network[0].strip()
            channel = network[3].strip()
            power = network[8].strip()
            essid = network[13].strip()

            n = Network(bssid, channel, power, essid)
            networks.append(n)    
        
        time.sleep(1)
        
    
# ---[ STEPS ]--- #

def reset_variables():
    for fname in os.listdir(__location__):
        if fname.startswith("tmp_"):
            os.remove(os.path.join(__location__, fname))

    adapters.clear()
    networks.clear()

def show_header():
    print("==> V-Kicker <==")
    print("")

def check_dependencies():
    if (is_root() == False):
        show_error("Run this script with sudo to continue.")
        sys.exit(1)

def find_adapters():
    show_msg("Searching for adapters.")

    adapters.clear()

    cmd = subprocess.run("ifconfig | grep wlan", shell = True, stdout = subprocess.PIPE)
    
    try:
        lines = cmd.stdout.decode("utf8").splitlines()
    except:
        show_error("Error while getting wlan adapters.")
        sys.exit(1)

    if len(lines) == 0:
        show_error("No wlan interfaces found.")
        sys.exit(1)
        
    for line in lines:
        iStart = line.find("wlan")
        iEnd = line.find(":")
        interface = line[iStart:iEnd - iStart]

        adapter = Adapter(interface, "mon" in line)
        adapters.append(adapter)

def choose_adapter():
    global choosen_adapter

    if has_monitor_adapter() != None:
        choosen_adapter = has_monitor_adapter()
    elif len(adapters) == 1:
        choosen_adapter = adapters[0]
    else:
        show_msg("Available adapters:")
        print("")

        for i, adapter in enumerate(adapters):
            print(" " + str(i) + ") " + adapter.name)

        print("")

        # TODO: check for int()
        iAdapter = int(show_question("Which adapter do you want to use?"))
        choosen_adapter = adapters[iAdapter]
    
    show_msg("Adapter " + choosen_adapter.name + " choosen.")

def airmon_check_kill():
    show_msg("Killing processes that uses " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng check kill", shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while killing processes.")
        sys.exit(1)

def enable_monitor_mode():
    show_msg("Enabling monitor mode for " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng start " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while enabling monitor mode.")
        sys.exit(1)

    show_msg("Monitor mode enabled for " + choosen_adapter.name + " adapter.")

def scan_access_points():
    show_msg("Scanning access points using " + choosen_adapter.name + " adapter.")

    global thread_network_scan
    thread_network_scan = Thread(target = threaded_network_scan)
    thread_network_scan.start()

    global thread_read_networks
    thread_read_networks = Thread(target = threaded_read_networks)
    thread_read_networks.start()

    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()

    try:
        while True:
            stdscr.addstr(0, 0, "[!] Available networks:")
            stdscr.addstr(1, 0, " ")

            for i, network in enumerate(networks):
                stdscr.addstr(i + 2, 0, "==> [" + network.bssid + "] - CH" + network.channel + " - PW" + network.power + " - " + network.essid)

            stdscr.addstr(len(networks) + 2, 0, " ")
            stdscr.addstr(len(networks) + 3, 0, "[!] Use CTRL + C to stop scanning.")

            stdscr.refresh()

            time.sleep(1)
    except KeyboardInterrupt:
        curses.echo()
        curses.nocbreak()
        curses.endwin()

        show_msg("Available networks:")
        print(" ")

        for i, network in enumerate(networks):
            print(" " + str(i) + ") [" + network.bssid + "] - CH" + network.channel + " - PW" + network.power + " - " + network.essid)
        
        print(" ")

        choosen_i_network = show_question("Choose a network:")

        global choosen_network
        choosen_network = networks[int(choosen_i_network)]

        show_msg("Network " + choosen_network.essid + " choosen")

# ---[ MAIN ]--- #

if __name__ == "__main__":
    reset_variables()
    show_header()
    check_dependencies()
    find_adapters()

    if has_monitor_adapter() == None:
        choose_adapter()
        airmon_check_kill()
        enable_monitor_mode()
        find_adapters()
        
    choose_adapter()
    scan_access_points()