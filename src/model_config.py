# coding=utf-8
import os


class ModelConfig:
    def __init__(self):
        pass

    # sampling stuff
    forecast_length = 24
    granularity = 10  # in minutes
    nary_thresh = 5
    accuracy = 1  # in minutes
    gap_threshold = 2


class DBConfig:
    def __init__(self):
        pass

    host = os.environ.get('SQL_HOST')
    port = int(os.environ.get('SQL_PORT'))
    source = os.environ.get('SQL_SOURCE')
    username = os.environ.get('SQL_USERNAME')
    password = os.environ.get('SQL_PASSWORD')
    weather_db_name = 'weather'
    weather_history_collection_name = 'history'
    weather_forecast_collection_name = 'forecast'
    client_db_name = 'west_end_646'
    client_table_name = {'occupancy': 'occupancy'}
    engine = 'postgresql://{}@{}:{}/{}'.format(username, host, port,
                                               client_table_name.get(
                                                   'occupancy'))
