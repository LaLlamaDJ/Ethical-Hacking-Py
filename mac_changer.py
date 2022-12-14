import subprocess
import optparse
import re

def get_args():
    parser = optparse.OptionParser()

    parser.add_option("-i", "--interface", dest = "interface", help="Interface to change MAC.")
    parser.add_option("-m", "--mac", dest = "new_mac", help="New MAC Address.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please indicate an interface, use --help for more information.")
    elif not options.new_mac:
        parser.error("[-] Please indicate a MAC address, use --help for more information.")

    return options

def change_mac (interface, new_mac):
    print("[+] Changing MAC address of " + interface + "to " + new_mac)

    subprocess.call(["ifconfig " + interface + " down"])
    subprocess.call(["ifconfig " + interface + " hw ether " + new_mac])
    subprocess.call(["ifconfig " + interface + " up"])

def get_current_mac(interface):
    ifconfig_results = subprocess.check_output("ifconfig", options.interface)
    print(ifconfig_results)

    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_results)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read mac address.")

options = get_args()
current_mac = get_current_mac(options.interface)

print("[INFO] Current MAC = " + str(current_mac))

change_mac(options.interface, options.new_mac)
change_mac = get_current_mac(options.interface)

if current_mac == options.new_mac:
    print("[+] MAC address was changed successfully to " + current_mac)
else:
    print("[-] MAC address was changed unsuccessfully.")