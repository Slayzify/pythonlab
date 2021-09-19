#!/usr/bin/env python

import re
import subprocess as shell
import optparse


def load_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address value")
    (opt, args) = parser.parse_args()

    if opt.new_mac is None:
        parser.error("[-] MAC Address value is missing!")
    elif opt.interface is None:
        parser.error("[-] Interface is missing!")

    return opt


def change_mac(opt):
    print("[+] Changing MAC Address for {0} to {1}".format(opt.interface, opt.new_mac))

    # Useful here too in order to check if interface in argument has MAC address. (ie. loopback has not..)
    get_current_mac(options.interface)

    shell.run(["ifconfig", opt.interface, "down"], check=True)
    shell.run(["ifconfig", opt.interface, "hw", "ether", opt.new_mac], check=True)
    shell.run(["ifconfig", opt.interface, "up"], check=True)

    if str(opt.new_mac) == get_current_mac(opt.interface):
        print("[+] MAC Address has been changed successfully")
    else:
        print(str(opt.new_mac))
        print(str(get_current_mac(opt.interface)))
        print("[-] Error. Could not update MAC Address")


def get_current_mac(interface):
    result = shell.check_output(["ifconfig", interface])
    mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(result))

    if mac is None:
        print("[-] Error. {0} interface has no MAC Address to assign.".format(interface))
        exit(-1)
    else:
        return mac.group(0)


if __name__ == "__main__":
    options = load_args()
    change_mac(options)
