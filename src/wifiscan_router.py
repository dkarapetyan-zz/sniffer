import threading
import json
import datetime

from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_dict = {}


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            new_info_dict = {'index': now, 'addr': pkt.addr2, 'info': pkt.info}
            base_dict.update(new_info_dict)
            write_dicts()

            print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def write_dicts():
    threading.Timer(900, things_to_be_written)


def things_to_be_written():
    with open("all_info.csv", 'w') as file:
        json.dump(base_dict, file)


def main():
    from datetime import datetime
    print("[%s] Starting scan" % datetime.now())
    sniff(iface="wlan0", prn=packet_handler)


if __name__ == "__main__":
    main()
