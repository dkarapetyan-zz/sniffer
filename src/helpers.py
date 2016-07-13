import logging.config
import os

from logging_config import lcfg

logging.config.dictConfig(lcfg)
logger = logging.getLogger()
import pandas as pd


def results_to_disk(df, data_name, outfile):
    try:
        base_dir = os.path.expanduser(os.path.dirname(outfile))
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        dframe = pd.DataFrame(df)
        dframe.index.name = 'time'
        dframe.to_csv(path_or_buf=outfile, index=False, mode='a')
        logger.info(
            "Wrote {} results to csv successfully.".format(
                data_name))

    except (RuntimeError, TypeError, NameError) as e:
        logger.critical("Failed to write some results to disk.")
        raise e
