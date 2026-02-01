from scapy.all import Ether, ARP, srp
import sys
def ARP_scan(subnet):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered = srp(packet,timeout=2)[0]
    devices = []
    for sent,received in answered:
        devices.append({"ip":received.psrc,"mac":received.hwsrc})
    return devices

if __name__ == "__main__":
    if(len(sys.argv)!=2):
        sys.exit(1)
    subnet = sys.argv[1]
    devices = ARP_scan(subnet)
    print("Found",len(devices),"Devices")
    for device in devices:
        print("IP: ",device["ip"])
        print("MAC: ",device["mac"])
