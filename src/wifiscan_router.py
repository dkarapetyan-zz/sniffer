import datetime
import csv
import logging
import logging.config

from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from logging_config import lcfg

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

logging.config.dictConfig(lcfg)
logger = logging.getLogger()

base_list = []


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            # new_info_list = [
            #     {'index': now, 'addr': pkt.addr2, 'info': pkt.info}]
            # base_list.extend(new_info_list)
            logging.info("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def write_dict(list_to_write):
    with open("/root/all_info.csv", 'wb') as file:
        logging.info("Writing results to file.")
        keys = list_to_write[0].keys()
        w = csv.DictWriter(file, keys)
        w.writeheader()
        w.writerows(list_to_write)


def main():
    logging.info("Starting scan")
    # writer = threading.Timer(900, write_dict, [base_list])
    # writer.start()
    sniff(iface="wlan0", prn=packet_handler)
