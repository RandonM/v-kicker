import curses
import os
import subprocess
import sys

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

# List of Adapter objects
adapters = []

# Choosen adapter
choosen_adapter = None

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

# ---[ STEPS ]--- #

def reset_variables():
    adapters.clear()

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

    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()

    # Execute
    # airodump-ng wlan0mon --write tmp_networks.csv --update 1 --output-format csv --write-interval 1
    # write output

    curses.echo()
    curses.nocbreak()
    curses.endwin()

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