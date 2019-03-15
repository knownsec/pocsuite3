from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.log import LOGGER

# logger
logger = LOGGER

# object to share within function and classes command
# line options and settings
conf = AttribDict()

# Dictionary storing
# (1)targets, (2)registeredPocs, (3) bruteMode
# (4)results, (5)pocFiles
# (6)multiThreadMode \ threadContinue \ threadException
kb = AttribDict()

# object to store original command line options
cmd_line_options = AttribDict()

# object to store merged options (command line, configuration file and default options)
merged_options = AttribDict()

# pocsuite paths
paths = AttribDict()
