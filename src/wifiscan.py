from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
ap_list = []


def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def main():
    from datetime import datetime
    print("[%s] Starting scan" % datetime.now())
    sniff(iface="mon0", prn=packet_handler)


if __name__ == "__main__":
    main()
