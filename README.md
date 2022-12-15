# V-Kicker

## What is it?

V-Kicker is a basic python script that allows the user to control who to kick from a wifi connection.
It uses `aircrack-ng` suite in order to enable monitor mode, scan access points and send deauth packets to clients.
Check if **wlan** card is compatible with **monitor mode**.
This scripts run perfectly on kali linux.

## How to use V-Kicker?

Ensure `python` and `aircrack-ng` dependency is installed and the **wlan** card is compatible with **monitor mode**.

Run `sudo python v-kicker.py`

## How to edit source?

Open **v-kicker.py** file and edit as you want. The entry point is towards the last lines. Sorry for bad python code, this is my really first python code, I usually code in c#.
