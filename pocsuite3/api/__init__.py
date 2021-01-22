from pocsuite3.lib.controller.controller import start
from pocsuite3.lib.core.common import single_time_warn_message, encoder_bash_payload, encoder_powershell_payload, \
    get_host_ipv6
from pocsuite3.lib.core.data import conf, kb, logger, paths
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.enums import PLUGIN_TYPE, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.option import init, init_options
from pocsuite3.lib.core.plugin import PluginBase, register_plugin
from pocsuite3.lib.core.poc import POCBase, Output
from pocsuite3.lib.core.register import (
    load_file_to_module,
    load_string_to_module,
    register_poc,
)
from pocsuite3.lib.core.settings import DEFAULT_LISTENER_PORT
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import get_middle_text, generate_shellcode_list, random_str
from pocsuite3.modules.ceye import CEye
from pocsuite3.modules.listener import REVERSE_PAYLOAD
from pocsuite3.modules.seebug import Seebug
from pocsuite3.modules.zoomeye import ZoomEye
from pocsuite3.modules.shodan import Shodan
from pocsuite3.modules.fofa import Fofa
from pocsuite3.modules.censys import Censys
from pocsuite3.modules.spider import crawl
from pocsuite3.modules.httpserver import PHTTPServer
from pocsuite3.shellcodes import OSShellcodes, WebShell
from pocsuite3.lib.core.interpreter_option import OptDict, OptIP, OptPort, OptBool, OptInteger, OptFloat, OptString, \
    OptItems, OptDict

__all__ = (
    'requests', 'PluginBase', 'register_plugin',
    'PLUGIN_TYPE', 'POCBase', 'Output', 'AttribDict', 'POC_CATEGORY', 'VUL_TYPE',
    'register_poc', 'conf', 'kb', 'logger', 'paths', 'DEFAULT_LISTENER_PORT', 'load_file_to_module',
    'load_string_to_module', 'single_time_warn_message', 'CEye', 'Seebug',
    'ZoomEye', 'Shodan', 'Fofa', 'Censys', 'PHTTPServer', 'REVERSE_PAYLOAD', 'get_listener_ip', 'get_listener_port',
    'get_results', 'init_pocsuite', 'start_pocsuite', 'get_poc_options', 'crawl',
    'OSShellcodes', 'WebShell', 'OptDict', 'OptIP', 'OptPort', 'OptBool', 'OptInteger', 'OptFloat', 'OptString',
    'OptItems', 'OptDict', 'get_middle_text', 'generate_shellcode_list', 'random_str', 'encoder_bash_payload',
    'encoder_powershell_payload', 'get_host_ipv6')


def get_listener_ip():
    return conf.connect_back_host


def get_listener_port():
    return conf.connect_back_port


def get_current_poc_obj():
    pass


def get_poc_options(poc_obj=None):
    poc_obj = poc_obj or kb.current_poc
    return poc_obj.get_options()


def get_results():
    return kb.results


def init_pocsuite(options={}):
    init_options(options)
    init()


def start_pocsuite():
    start()
