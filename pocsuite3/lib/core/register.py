import importlib.machinery
import importlib.util
from importlib.abc import Loader

from pocsuite3.lib.core.common import (
    multiple_replace, get_filename, get_md5,
    is_pocsuite3_poc, get_poc_requires, get_poc_name)
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.settings import POC_IMPORTDICT


class PocLoader(Loader):
    def __init__(self, fullname, path):
        self.fullname = fullname
        self.path = path
        self.data = None

    def set_data(self, data):
        self.data = data

    def get_filename(self, fullname):
        return self.path

    def get_data(self, filename):
        if filename.startswith('pocsuite://') and self.data:
            if not is_pocsuite3_poc(self.data):
                data = multiple_replace(self.data, POC_IMPORTDICT)
            else:
                data = self.data
        else:
            with open(filename, encoding='utf-8') as f:
                code = f.read()
            if not is_pocsuite3_poc(code):
                data = multiple_replace(code, POC_IMPORTDICT)
            else:
                data = code
        return data

    @staticmethod
    def check_requires(data):
        requires = get_poc_requires(data)
        requires = [i.strip().strip('"').strip("'") for i in requires.split(',')] if requires else ['']
        if requires[0]:
            poc_name = get_poc_name(data)
            info_msg = 'PoC script "{0}" requires "{1}" to be installed'.format(poc_name, ','.join(requires))
            logger.info(info_msg)
            try:
                for r in requires:
                    __import__(r)
            except ImportError:
                err_msg = 'try install with "python -m pip install {0}"'.format(r)
                logger.error(err_msg)
                raise SystemExit

    def exec_module(self, module):
        filename = self.get_filename(self.fullname)
        poc_code = self.get_data(filename)
        self.check_requires(poc_code)
        obj = compile(poc_code, filename, 'exec', dont_inherit=True, optimize=-1)
        exec(obj, module.__dict__)


def load_file_to_module(file_path):
    if '' not in importlib.machinery.SOURCE_SUFFIXES:
        importlib.machinery.SOURCE_SUFFIXES.append('')
    try:
        module_name = 'pocs_{0}'.format(get_filename(file_path, with_ext=False))
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=PocLoader(module_name, file_path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    except ImportError:
        error_msg = "load module failed! '{}'".format(file_path)
        logger.error(error_msg)
        raise


def load_string_to_module(code_string, fullname=None):
    try:
        module_name = 'pocs_{0}'.format(get_md5(code_string)) if fullname is None else fullname
        file_path = 'pocsuite://{0}'.format(module_name)
        poc_loader = PocLoader(module_name, file_path)
        poc_loader.set_data(code_string)
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise


def register_poc(poc_class):
    module = poc_class.__module__.split('.')[0]
    if module in kb.registered_pocs:
        return

    kb.registered_pocs[module] = poc_class()
    kb.current_poc = kb.registered_pocs[module]
