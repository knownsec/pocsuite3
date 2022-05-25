__title__ = 'pocsuite3'
__version__ = '1.9.3'
__author__ = 'Knownsec 404 Team'
__author_email__ = '404-team@knownsec.com'
__license__ = 'GPLv2'
__copyright__ = 'Copyright 2014-2022 Knownsec 404 Team'
__name__ = 'pocsuite3'
__package__ = 'pocsuite3'

from .lib.core.common import set_paths
from .cli import module_path


set_paths(module_path())
