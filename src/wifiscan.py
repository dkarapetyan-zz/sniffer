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
        new_info_df.to_sql(db_config_init.sniffed_table_name,
                           con=db_config_init.engine,
                           schema=db_config_init.schema,
                           if_exists='append', index=True,
                           index_label='datetime')
        logging.info("AP MAC: %s " % pkt.addr2)


def occupancy_counter(df):
    counts_ts = df['mac'].value_counts()
    non_outside_ts = counts_ts[
        counts_ts > counts_ts.quantile(ModelConfig.quantile_bound)]
    import ipdb
    ipdb.set_trace()
    return len(non_outside_ts)


def occupancy_write():
    # noinspection SqlResolve
    query = "select * from {}.{} where " \
            "datetime > " \
            "CURRENT_TIMESTAMP AT TIME ZONE 'UTC' - INTERVAL '{} " \
            "minutes'".format(db_config_init.schema,
                              db_config_init.sniffed_table_name,
                              ModelConfig.gran)
    base_df = pd.read_sql(query, con=db_config_init.engine)
    now = base_df.index[-1]
    if len(base_df) != 0:
        try:
            table = db_config_init.occupancy_table_name
            occupancy_df = pd.DataFrame(
                data={table: occupancy_counter(base_df)},
                index=[now])
            occupancy_df.to_sql(
                table, con=db_config_init.engine,
                schema=db_config_init.schema,
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
