import datetime
import logging.config
import threading

import pandas as pd
from numpy import logical_and
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff
from sqlalchemy import create_engine

from logging_config import lcfg
from model_config import ModelConfig, DBConfig

engine = create_engine(DBConfig.engine)
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
                data=[pkt.addr2, pkt.info],
                index=[now])
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


def things_to_be_written():
    t = threading.Timer(60 * ModelConfig.granularity, things_to_be_written)
    t.start()
    global base_df
    if len(base_df) == 0:
        return
    try:
        now = datetime.datetime.utcnow()
        occupancy_df = pd.DataFrame(
            data={'occupancy': occupancy_counter(base_df)},
            index=[now])
        logging.info("Writing to DB.")

        tables = ["all_info", "occupancy"]
        dfs = [base_df, occupancy_df]

        for df, table in zip(dfs, tables):
            df.to_sql(table, con=engine, schema='occupancy_schema',
                      if_exists='append', index=True, index_label='datetime')

        base_df = pd.DataFrame()

    except (RuntimeError, TypeError, NameError) as e:
        logger.critical("Failed to append some results to DB.")
        raise e


def main(the_device):
    logging.info("Starting scan")
    things_to_be_written()
    sniff(iface=the_device, prn=packet_handler, store=0)
