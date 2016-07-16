import datetime
import logging.config
import threading

import pandas as pd
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

from logging_config import lcfg
from model_config import DBConfig, ModelConfig

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_df = pd.DataFrame()

logging.config.dictConfig(lcfg)
logger = logging.getLogger()


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE and pkt.info == '':
            new_info_df = pd.DataFrame(
                data={'mac': pkt.addr2},
                index=[now])
            global base_df
            base_df = base_df.append(new_info_df)
            logging.info("AP MAC: %s " % pkt.addr2)


def occupancy_counter(df=pd.DataFrame()):
    df_subset = df.drop_duplicates()
    return len(df_subset)


def things_to_be_written():
    global base_df
    if len(base_df) != 0:
        try:
            now = datetime.datetime.utcnow()
            occupancy_df = pd.DataFrame(
                data={'occupancy': occupancy_counter(base_df)},
                index=[now])

            tables = ["all_info", "occupancy"]
            dfs = [base_df, occupancy_df]
            db_config_init = DBConfig('west_end_646')
            for df, table in zip(dfs, tables):
                df.to_sql(table, con=db_config_init.engine,
                          schema='occupancy_schema',
                          if_exists='append', index=True,
                          index_label='datetime')
                logging.info("Appended to {} table".format(table))
            base_df = pd.DataFrame()

        except Exception:
            logger.critical("Failed to append some results to DB.")
            raise


def main(the_device):
    t = threading.Timer(ModelConfig.gran_seconds, things_to_be_written)
    t.start()
    logging.info("Starting scan")
    sniff(iface=the_device, prn=packet_handler, store=0)
