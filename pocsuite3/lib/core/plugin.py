import os

from pocsuite3.lib.core.common import is_pocsuite3_poc, single_time_warn_message
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.register import load_string_to_module, load_file_to_module


class PluginBase(object):

    def __init__(self):
        pass

    def get_category(self):
        return self.category

    def add_target(self, target):
        ret = False
        if isinstance(target, bytes):
            target = target.decode()

        if isinstance(target, str):
            kb.targets.add(target)
            ret = True
        else:
            err_msg = "[PLUGIN] invalid target format: {0}".format(target)
            logger.error(err_msg)

        return ret

    def add_poc(self, poc, fullname=None):
        ret = False
        poc = self.format_poc(poc)
        if self.check_poc(poc):
            try:
                load_string_to_module(poc, fullname)
                ret = True
            except Exception as ex:
                msg = "[PLUGIN] load PoC script failed: {0}".format(str(ex))
                single_time_warn_message(msg)
        else:
            err_msg = "[PLUGIN] invalid pocsuite3 PoC code"
            logger.error(err_msg)
        return ret

    def add_poc_from_file(self, filename):
        ret = False

        if os.path.exists(filename):
            try:
                load_file_to_module(filename)
                ret = True
            except SystemExit:
                pass
            except Exception as ex:
                msg = "[PLUGIN] load PoC script failed: {0}".format(str(ex))
                single_time_warn_message(msg)
        else:
            err_msg = "[PLUGIN] invalid pocsuite3 PoC file {}".format(filename)
            logger.error(err_msg)
        return ret

    @staticmethod
    def format_poc(poc):
        if isinstance(poc, bytes):
            poc = poc.decode()
        return poc

    @staticmethod
    def check_poc(poc):
        return is_pocsuite3_poc(poc)

    @staticmethod
    def get_results():
        return kb.results

    def init(self):
        raise NotImplementedError

    def start(self):
        raise NotImplementedError

    def handle(self, output):
        pass


def register_plugin(plugin_class):
    plugin_name = plugin_class.__module__.split('.')[0]
    plugin_category = plugin_class.category

    if plugin_name not in kb.plugins[plugin_category]:
        kb.plugins[plugin_category][plugin_name] = plugin_class()
