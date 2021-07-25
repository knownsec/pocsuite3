import sys
import logging
import colorlog
from pocsuite3.lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.SYSINFO, "*")
logging.addLevelName(CUSTOM_LOGGING.SUCCESS, "+")
logging.addLevelName(CUSTOM_LOGGING.ERROR, "-")
logging.addLevelName(CUSTOM_LOGGING.WARNING, "!")

LOGGER = logging.getLogger("pocsuite")

LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

FORMATTER = colorlog.LevelFormatter(
    fmt={
        "DEBUG": "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s",
        "INFO": "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s",
        "WARNING": "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s",
        "ERROR": "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s",
        "CRITICAL": "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s",
        "*": "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s",
        "+": "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s",
        "-": "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s",
        "!": "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s"
    },
    datefmt="%H:%M:%S",
    log_colors={
        '*': 'cyan',
        '+': 'green',
        '-': 'red',
        '!': 'yellow',
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bg_red,white'
    },
    secondary_log_colors={},
    style='%'
)

disableColor = "disable-col" in ' '.join(sys.argv)
if disableColor:
    FORMATTER = logging.Formatter(
        "\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")


LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)
