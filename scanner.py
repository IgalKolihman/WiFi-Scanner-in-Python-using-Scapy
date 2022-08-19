"""Scans a network interface for beacon packets (SSID)

Usage:
    scanner.py -h | --help
    scanner.py -i <interface>
    scanner.py -l | --list

Options:
    -h --help   Show this help message
    -i          Network interface to sniff packets from
    -l --list   List the available interfaces
"""
import os
import time
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

import docopt
from threading import Thread

import psutil
import tabulate
from wifi import Cell
from wifi.exceptions import InterfaceError

headers = ["SSID", "Address", "Chnl", "Sig", "Last seen"]
networks = {}

# create logger with 'spam_application'
logger = logging.getLogger('scanner')
logger.setLevel(logging.DEBUG)
fh = RotatingFileHandler('/home/pi/network_scanner.log', maxBytes=1000000, backupCount=2)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
fh.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)


def _get_timestamp():
    return datetime.utcfromtimestamp(time.time()).strftime("%d/%m %H:%M:%S")


def _list_networks():
    networks_list = []
    for net in sorted(networks):
        networks_list.append([net] + networks[net])

    return networks_list


def scan_networks(interface):
    while True:
        try:
            cells = Cell.all(interface)
        except InterfaceError:
            print(
                f"Interface {interface} was busy (Or some other error occurred). Trying again..."
            )
            time.sleep(1)
            continue

        # Loop over the available cells
        for cell in cells:
            ssid = f"{cell.ssid[:15]} ({cell.frequency[:3]})"
            networks[ssid] = [
                cell.address,
                cell.channel,
                cell.signal,
                _get_timestamp(),
            ]
            logger.info(f"{_get_timestamp()} | "
                        f"{cell.address} | "
                        f"{cell.channel} | "
                        f"{cell.signal} | "
                        f"{ssid}")

        time.sleep(5)


def print_all():
    while True:
        os.system("clear")
        print(tabulate.tabulate(_list_networks(), headers=headers, tablefmt="pretty"))
        time.sleep(10)


def display_interfaces():
    addrs = psutil.net_if_addrs()
    for interface in addrs.keys():
        print(interface)


if __name__ == "__main__":
    args = docopt.docopt(__doc__)
    if args["--list"]:
        display_interfaces()
        exit()

    interface = args["<interface>"]

    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    scan_networks(interface)

    # # start the channel changer
    # channel_changer = Thread(target=change_channel)
    # channel_changer.daemon = True
    # channel_changer.start()
