import datetime
import logging.config
import os
import threading

import pandas as pd
from numpy import logical_and
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from logging_config import lcfg
from model_config import ModelConfig

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_df = pd.DataFrame()

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
            logging.info("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def occupancy_counter(df=pd.DataFrame()):
    now = datetime.datetime.utcnow()
    past = now - datetime.timedelta(minutes=ModelConfig.granularity)
    time_range = logical_and(df.index >= past, df.index <= now)
    df_subset = df[time_range]
    df_subset = df_subset.drop_duplicates()
    return len(df_subset)


def things_to_be_written(base_dir=os.path.expanduser("~pi/.sniffer/csvs/")):
    try:
        now = datetime.datetime.utcnow()
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        global base_df
        logging.info("Writing to file.")
        base_df.to_csv(base_dir + "all_info.csv", mode='a', header=False)
        occupancy_ts = pd.Series(data=occupancy_counter(base_df),
                                 index=[now])
        occupancy_ts.to_csv(base_dir + "occupancy.csv", mode='a',
                            header=False)
        base_df = pd.DataFrame()
        t = threading.Timer(60 * ModelConfig.granularity, things_to_be_written)
        t.start()
    except (RuntimeError, TypeError, NameError) as e:
        logger.critical("Failed to write some results to disk.")
        raise e


def main(the_device):
    logging.info("Starting scan")
    things_to_be_written()
    sniff(iface=the_device, prn=packet_handler, store=0)
