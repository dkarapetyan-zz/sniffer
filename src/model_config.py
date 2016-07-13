# coding=utf-8


class ModelConfig:
    def __init__(self):
        pass

    # sampling stuff
    forecast_length = 24
    granularity = 10  # in minutes
    nary_thresh = 5
    accuracy = 1  # in minutes
    gap_threshold = 2
