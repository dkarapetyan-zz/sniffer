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
db_config_init = DBConfig('west_end_646')


def packet_handler(pkt):
    now = datetime.datetime.utcnow()
    if pkt.haslayer(Dot11) and pkt.type == PROBE_REQUEST_TYPE and pkt.subtype \
            == PROBE_REQUEST_SUBTYPE and pkt.info == '':
        new_info_df = pd.DataFrame(
            data={'mac': pkt.addr2},
            index=[now])
        new_info_df.to_sql("all_info", con=db_config_init.engine,
                           schema='occupancy_schema',
                           if_exists='append', index=True,
                           index_label='datetime')
        logging.info("AP MAC: %s " % pkt.addr2)


def occupancy_counter(df=pd.DataFrame()):
    df_subset = df.drop_duplicates()
    return len(df_subset)


def occupancy_write():
    query = "select * from occupancy_schema.all_info where datetime > " \
            "CURRENT_TIMESTAMP - INTERVAL '{} minutes'".format(ModelConfig.gran)
    base_df = pd.read_sql(query, con=db_config_init.engine)
    if len(base_df) != 0:
        try:
            now = datetime.datetime.utcnow()
            occupancy_df = pd.DataFrame(
                data={'occupancy': occupancy_counter(base_df)},
                index=[now])
            table = "occupancy"
            occupancy_df.to_sql(
                table, con=db_config_init.engine,
                schema="occupancy_schema",
                if_exists='append', index=True,
                index_label='datetime')
            logging.info("Appended to {} table".format(table))
        except Exception:
            logger.critical("Failed to append some results to DB.")
            raise
    t = threading.Timer(ModelConfig.gran * 60, occupancy_write)
    t.start()


def main(the_device):
    occupancy_write()
    logging.info("Starting scan")
    sniff(iface=the_device, prn=packet_handler, store=0)
