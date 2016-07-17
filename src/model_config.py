# coding=utf-8
import os

from sqlalchemy import create_engine


class ModelConfig:
    def __init__(self):
        pass

    # sampling stuff
    forecast_length = 24
    gran = 10  # in minutes
    nary_thresh = 5
    accuracy = 1  # in minutes
    gap_threshold = 2


class DBConfig:
    host = os.environ.get('SQL_HOST')
    port = int(os.environ.get('SQL_PORT'))
    source = os.environ.get('SQL_SOURCE')
    username = os.environ.get('SQL_USERNAME')
    password = os.environ.get('SQL_PASSWORD')
    weather_db_name = 'weather'
    weather_history_collection_name = 'history'
    weather_forecast_collection_name = 'forecast'
    sniffed_table_name = 'sniffed'

    def __init__(self, client):
        self.schema = client
        self.engine = create_engine(
            'postgresql://{}:{}@{}:{}/postgres'.format(
                self.username,
                self.password,
                self.host,
                self.port))
