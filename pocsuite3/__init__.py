__title__ = 'pocsuite'
__version__ = '1.6.0'
__author__ = 'Knownsec Security Team'
__author_email__ = 's1@seebug.org'
__license__ = 'GPLv2+'
__copyright__ = 'Copyright 2018 Knownsec'
__name__ = 'pocsuite3'
__package__ = 'pocsuite3'

from .lib.core.common import set_paths
from .cli import module_path


set_paths(module_path())
