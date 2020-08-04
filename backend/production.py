import os

P = (
    "00b0bd0679a743d362eeaa68d6dacf"
    "065657d26d170208139c3f486dd11e"
    "facf0219c21c80cc55ed11b9e5874a"
    "c95d46de13e4f2b9f69d033fb2edce"
    "10e6d4209c0c11f6f4ed0de7e8a2d4"
    "0e66eeafe7743b5507bd2e1571f744"
    "cda42cb7647dd1d90bb0c92c3b9665"
    "16b968439eb4659944477daa2ce8c6"
    "479544f9a5fce7e4628126b41b99ee"
    "e93f92928d267fa541924f7278ce95"
    "709387915a7b2a64317e1bd61b36dd"
    "556cd3c2fbc5f2f61455b58abfd1c9"
    "3587e18124c0b63779a296b96757b5"
    "43530a6aba0c9b67b461ee834a3974"
    "dd7d52c1f3f0b0d9bf81e26a6f615d"
    "51c51308adfcbb310bfe26faa2254e"
    "4f61b7e41a88b99b5efe913624fe3f"
    "a16b"
)
PUBLIC_KEY = 65537
PRIVATE_KEY = (
    "57fcd3236f7d59d8afff10909e8060"
    "a44db689eee16909f248a31360ffee"
    "576eb14a2d0c862de5076527fb11e5"
    "6bd5a32bfe5844f29cba8854d90534"
    "eee5fe92118444112d8f35bc608bf7"
    "db90caec0cb6991f70346822c3ba72"
    "3260bcb07fdf20122ce20a6e63f251"
    "bcde4683d5459b671dbc572362838c"
    "11a9342c49db5c9c44eaae053dbae6"
    "6a9e743e73f40bfbd2a1bcd0829c86"
    "2c6ef63a7dbba46545a903a97b2f37"
    "b229d4fec8cd1d57adfac2e576af8e"
    "0ee23a1047854c11cc677bf788d532"
    "e91b9d2dde48308d80e26e0c7c745c"
    "a27080bb2b7151e060240b4847cb92"
    "75add5fae455a97ee18b6c4e608b5c"
    "533a3c6b7fecd336d04ea0b3f8de3f"
    "19"
)

DEFAULT_TOKEN_EXPIRE = {
    # if the user doesn't use the token in this period token expires.
    'PER_USE': 24 * 60 * 60,
    # the token expires after this time.
    'TOTAL': 10 * 24 * 60 * 60
}

# Logging config
# You may want to uncomment mail handler in production!
# you should get the logger like this whenever you need it: logging.getLogger(__name__)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)-8s [%(module)s:%(funcName)s:%(lineno)d]: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'formatter': 'verbose',
            'filename': os.path.join(BASE_DIR, '.important.log')
        },
        'sentry': {
            'level': 'CRITICAL',
            'class': 'raven.contrib.django.handlers.SentryHandler',
        },
        # 'mail': {
        #     'level': 'CRITICAL',
        #     'class': 'django.utils.log.AdminEmailHandler',
        #     'formatter': 'verbose',
        # },
    },
    'loggers': {
        'core': {
            'handlers': ['console', 'file', 'sentry'],
            'propagate': True,
            'level': LOG_LEVEL,
        }
    }
}

import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn="https://ce6d39619ff24a2f9b18f66846360de6@o428081.ingest.sentry.io/5373053",
    integrations=[DjangoIntegration()],

    # If you wish to associate users to errors (assuming you are using
    # django.contrib.auth) you may enable sending PII data.
    send_default_pii=True
)

RAVEN_CONFIG = {
    'dsn': 'https://ce6d39619ff24a2f9b18f66846360de6@o428081.ingest.sentry.io/5373053',
}

MAX_FILE_SIZE = 10**6

MAX_TRY = 9
MAX_TIME_TRY = 5 * 60

ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '192.168.1.107']
