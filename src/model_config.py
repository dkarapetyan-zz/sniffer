# coding=utf-8
# import os

class ModelConfig:
    def __init__(self):
        pass

    # sampling stuff
    forecast_length = 24
    granularity = 10  # in minutes
    nary_thresh = 5
    accuracy = 1  # in minutes
    gap_threshold = 2


    # class DBConfig:
    #     def __init__(self):
    #         pass
    #
    #     url = 'postgresql://postgres@74.71.229.106:5432/'
    #     user = 'postgres'
    #     username = os.environ.get('DB_USERNAME')
    #     password = os.environ.get('DB_PASSWORD')
    #     weather_db_name = 'weather'
    #     weather_history_collection_name = 'history'
    #     weather_forecast_collection_name = 'forecast'
    #     building_db_name = 'skynet'
    #     building_collection_name = 'timeseries'
