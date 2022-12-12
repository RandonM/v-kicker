import os
import subprocess
import sys

# ---[ CLASSES ] --- #

class Adapter:
  def __init__(self, name):
    self.name = name

# ---[ GLOBAL VARIABLES ] --- #

# List of Adapter objects
adapters = []

# Choosen adapter
choosen_adapter = None

# ---[ MANAGEMENT ] --- #

def is_root():
    return os.geteuid() == 0

def show_error(msg):
    print("[x]: " + msg)

def show_msg(msg):
    print("[!]: " + msg)

def show_question(msg):
    return input("[?]: " + msg + " ")

# ---[ STEPS ] --- #

def reset_variables():
    adapters.clear()

def show_header():
    print("==> V-Kicker <==")
    print("")

def check_dependencies():
    if (is_root == False):
        show_error("Run this script with sudo to continue.")
        sys.exit(1)

def find_adapters():
    cmd = subprocess.run("ifconfig | grep wlan", shell = True, stdout = subprocess.PIPE)
    out = cmd.stdout.decode("utf8")
    # TODO: what happen if out variable contains multiple lines?

    iStart = out.find("wlan")
    iEnd = out.find(":")
    interface = out[iStart:iEnd - iStart]

    adapter = Adapter(interface)

    adapters.append(adapter)

def show_adapters():
    show_msg("Available adapters:")
    print("")

    for i, adapter in enumerate(adapters):
        print("[" + str(i) + "] " + adapter.name)

    print("")

def choose_adapter():
    # TODO: check for int()
    iAdapter = int(show_question("Which adapter do you want to use?"))
    global choosen_adapter
    choosen_adapter = adapters[iAdapter]

def airmon_check_kill():
    show_msg("Killing processes that uses " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng check kill", shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while killing processes.")
        sys.exit(1)

def enable_monitor_mode():
    show_msg("Enabling monitor mode for " + choosen_adapter.name + " adapter.")
    cmd = subprocess.run("airmon-ng start " + choose_adapter.name, shell = True, stdout = subprocess.PIPE)

    if cmd.returncode != 0:
        show_error("Error while enabling monitor mode.")
        sys.exit(1)

# ---[ MAIN ] --- #

if __name__ == "__main__":
    reset_variables()
    show_header()
    check_dependencies()
    find_adapters()
    show_adapters()
    choose_adapter()
    airmon_check_kill()
    enable_monitor_mode()