import threading

from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff
import pandas as pd

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4
base_df = pd.DataFrame()
occupancy_series = pd.Series()


def packet_handler(pkt):
    now = pd.Timestamp.utcnow()
    if pkt.haslayer(Dot11):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == \
                PROBE_REQUEST_SUBTYPE:
            new_info_df = pd.DataFrame(
                data={'addr': pkt.addr2, 'info': pkt.info},
                index=now)
            base_df.append(new_info_df)
            new_occ_ts = pd.Series(data=occupancy_counter(base_df), index=now)
            occupancy_series.append(new_occ_ts)
            write_csvs()

            print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))


def occupancy_counter(df):
    now = pd.Timestamp.utcnow()
    df_subset = df.between_time(now - pd.Timedelta('15 min'))
    df_subset.drop_duplicates(inplace=True, keep=last)
    return len(df_subset)


def write_csvs():
    threading.Timer(900, things_to_be_written)


def things_to_be_written():
    base_df.to_csv("all_info.csv")
    occupancy_series.to_csv("occupancy.csv")


def main():
    from datetime import datetime
    print("[%s] Starting scan" % datetime.now())
    sniff(iface="wlan0", prn=packet_handler)


if __name__ == "__main__":
    main()
