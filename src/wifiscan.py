import datetime
import logging.config
import threading

import pandas as pd
from numpy import logical_and
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from logging_config import lcfg

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_df = pd.DataFrame()
occupancy_series = pd.Series()

logging.config.dictConfig(lcfg)
logger = logging.getLogger()


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            new_info_df = pd.DataFrame(
                data={'addr': pkt.addr2, 'info': pkt.info}, index=[now])
            global base_df
            base_df = base_df.append(new_info_df)
            new_occ_ts = pd.Series(data=occupancy_counter(base_df), index=[now])
            global occupancy_series
            occupancy_series = occupancy_series.append(new_occ_ts)
            logging.info("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def occupancy_counter(df=pd.DataFrame()):
    now = datetime.datetime.utcnow()
    past = now - datetime.timedelta(minutes=15)
    time_range = logical_and(df.index >= past, df.index <= now)
    df_subset = df[time_range]
    df_subset = df_subset.drop_duplicates()
    return len(df_subset)


def things_to_be_written():
    global base_df
    global occupancy_series
    logging.info("Writing to file.")
    base_df.to_csv("all_info.csv", mode='a', header=False)
    occ_final_reading = occupancy_series.tail(1)
    occ_final_reading.to_csv("occupancy.csv", mode='a', header=False)
    base_df = pd.DataFrame()
    occupancy_series = pd.Series()
    t = threading.Timer(60, things_to_be_written)
    t.start()


def main(the_device):
    logging.info("Starting scan")
    things_to_be_written()
    sniff(iface=the_device, prn=packet_handler, store=0)
