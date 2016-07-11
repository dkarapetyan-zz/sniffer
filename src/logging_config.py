import os

log_dir = os.path.expanduser('~') + "/logs/"
log_file = log_dir + "occupancy_sniff.log"

# if directory doesn't exist, create it
if not os.path.isdir(log_dir):
    os.makedirs(log_dir)
# if log doesn't exist, create it
fp = open(log_file, "a")
fp.close()

lcfg = {
    'version': 1,
    'formatters': {
        'simple': {
            'format': '%(asctime)s - %(levelname)s - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'level': 'DEBUG',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'level': 'DEBUG',
            'filename': log_file,
            'maxBytes': 1024,
            'backupCount': 0  # grow indefinitely--can change to roll in future
        },
        'timed_file': {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'simple',
            'level': 'DEBUG',
            'filename': log_file,
            'when': 'midnight',
            'utc': True,
            'interval': 1,
            'backupCount': 7
        },
        'sys': {
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'simple',
            'level': 'DEBUG',
        }
    },
    'root': {
        'handlers': ['console', 'file', 'sys'],
        'level': 'INFO'
    }
    # custom loggers, which will be child objects of root logger defined above
    # 'loggers': {
    #     'root': {
    #         'handlers': ['console', 'file', 'sys'],
    #         'level': 'INFO'
    #     }
    #  }
}
