from scapy.all import Ether, ARP, srp
from datetime import datetime, timezone
import netifaces
import sys
import ipaddress
def ARP_scan(subnet,iface):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered = srp(packet,iface=iface,timeout=2)[0]
    devices = []
    for sent,received in answered:
        devices.append({"ip":received.psrc,"mac":received.hwsrc})
    return devices

def get_interface_info(iface):
    addresses = netifaces.ifaddresses(iface)

    if netifaces.AF_INET not in addresses:
        return None  

    return addresses[netifaces.AF_INET][0]["addr"],addresses[netifaces.AF_INET][0]["netmask"]

if __name__ == "__main__":
    if(len(sys.argv)!=2):
        sys.exit(1)
    iface = sys.argv[1]

    info = get_interface_info(iface)
    if info is None:
        sys.exit(1)
    interface_ip, netmask = info
    subnet = str(ipaddress.IPv4Network(f"{interface_ip}/{netmask}", strict=False) )
    devices = ARP_scan(subnet,iface)
    print("Found",len(devices),"Devices")
    for device in devices:
        print("IP: ",device["ip"])
        print("MAC: ",device["mac"])
    timestamp = datetime.now(timezone.utc).isoformat()
    network_snapshot = {"meta":{
        "interface":iface,
        "interface_ip":interface_ip,
        "subnet":subnet,
        "timestamp":timestamp
        },
        "devices":devices
    }