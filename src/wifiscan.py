import datetime
import threading

import pandas as pd
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_df = pd.DataFrame()
occupancy_series = pd.Series()

import logging.config
from logging_config import lcfg

logging.config.dictConfig(lcfg)
logger = logging.getLogger()


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            new_info_df = pd.DataFrame(
                data={'addr': pkt.addr2, 'info': pkt.info},
                index=[now])
            base_df.append(new_info_df)
            new_occ_ts = pd.Series(data=occupancy_counter(base_df), index=[now])
            occupancy_series.append(new_occ_ts)
            logging.info("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def occupancy_counter(df=pd.DataFrame()):
    now = datetime.datetime.utcnow()
    past = now - datetime.timedelta(minutes=15)
    df_subset = df.between_time(start_time=now, end_time=past)
    df_subset = df_subset.drop_duplicates(df_subset, keep='last')
    return len(df_subset)


def things_to_be_written():
    base_df.to_csv("all_info.csv")
    occupancy_series.to_csv("occupancy.csv")


def main(the_device):
    logging.info("Starting scan")
    threading.Timer(100, things_to_be_written)
    sniff(iface=the_device, prn=packet_handler)
