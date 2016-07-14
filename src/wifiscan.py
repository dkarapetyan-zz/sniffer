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
cols_in_pkt = ['addr', 'info']
base_df = pd.DataFrame(columns=cols_in_pkt)

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
    t = threading.Timer(60 * ModelConfig.granularity, things_to_be_written)
    t.start()
    global base_df
    if len(base_df) == 0:
        return
    try:
        now = datetime.datetime.utcnow()
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        occupancy_df = pd.DataFrame(
            data={'occupancy': occupancy_counter(base_df)},
            index=[now])
        logging.info("Writing to file.")

        all_info_file = base_dir + "all_info.csv"
        occupancy_file = base_dir + "occupancy.csv"

        files = [all_info_file, occupancy_file]
        dfs = [base_df, occupancy_df]

        for df, fp in zip(dfs, files):
            if not os.path.isfile(fp):
                df.to_csv(fp, mode='w', header=True, index_label='index')
            else:
                df.to_csv(fp, mode='a', header=False)

        base_df = pd.DataFrame(columns=cols_in_pkt)

    except (RuntimeError, TypeError, NameError) as e:
        logger.critical("Failed to write some results to disk.")
        raise e


def main(the_device):
    logging.info("Starting scan")
    things_to_be_written()
    sniff(iface=the_device, prn=packet_handler, store=0)
