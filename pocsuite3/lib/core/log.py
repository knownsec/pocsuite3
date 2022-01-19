import sys
import logging
import colorlog
from pocsuite3.lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.SYSINFO, "*")
logging.addLevelName(CUSTOM_LOGGING.SUCCESS, "+")
logging.addLevelName(CUSTOM_LOGGING.ERROR, "-")
logging.addLevelName(CUSTOM_LOGGING.WARNING, "!")

LOGGER = logging.getLogger("pocsuite")
try:
    # for python>=3.7
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    # http://www.macfreek.nl/memory/Encoding_of_Python_stdout
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
LOGGER_HANDLER = logging.StreamHandler(sys.stdout)
PRIMARY_FMT = (
    "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s"
)
CUSTOM_FMT = "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s"

FORMATTER = colorlog.LevelFormatter(
    fmt={
        "DEBUG": PRIMARY_FMT,
        "INFO": PRIMARY_FMT,
        "WARNING": PRIMARY_FMT,
        "ERROR": PRIMARY_FMT,
        "CRITICAL": PRIMARY_FMT,
        "*": CUSTOM_FMT,
        "+": CUSTOM_FMT,
        "-": CUSTOM_FMT,
        "!": CUSTOM_FMT
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
        "[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")


LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)
