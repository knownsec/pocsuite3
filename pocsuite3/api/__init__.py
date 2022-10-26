import base64
import binascii
import collections
import json
import os
import re
import socket
import ssl
import struct
import textwrap
import time
import urllib
import zlib

from pocsuite3.lib.controller.controller import start
from pocsuite3.lib.core.common import (OrderedDict, OrderedSet, check_port,
                                       encoder_bash_payload,
                                       encoder_powershell_payload, get_host_ip,
                                       get_host_ipv6, mosaic,
                                       single_time_warn_message, urlparse)
from pocsuite3.lib.core.data import conf, kb, logger, paths
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.enums import PLUGIN_TYPE, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import (OptBool, OptDict, OptFloat,
                                                   OptInteger, OptIP, OptItems,
                                                   OptPort, OptString)
from pocsuite3.lib.core.option import init, init_options
from pocsuite3.lib.core.plugin import PluginBase, register_plugin
from pocsuite3.lib.core.poc import Output, POCBase
from pocsuite3.lib.core.register import (load_file_to_module,
                                         load_string_to_module, register_poc)
from pocsuite3.lib.core.settings import DEFAULT_LISTENER_PORT
from pocsuite3.lib.request import requests
from pocsuite3.lib.utils import (generate_shellcode_list, get_middle_text,
                                 minimum_version_required, random_str)
from pocsuite3.lib.yaml.nuclei import Nuclei
from pocsuite3.modules.censys import Censys
from pocsuite3.modules.ceye import CEye
from pocsuite3.modules.fofa import Fofa
from pocsuite3.modules.httpserver import PHTTPServer
from pocsuite3.modules.hunter import Hunter
from pocsuite3.modules.interactsh import Interactsh
from pocsuite3.modules.listener import (BIND_PAYLOAD, REVERSE_PAYLOAD,
                                        bind_shell, bind_tcp_shell,
                                        bind_telnet_shell)
from pocsuite3.modules.quake import Quake
from pocsuite3.modules.seebug import Seebug
from pocsuite3.modules.shodan import Shodan
from pocsuite3.modules.spider import crawl
from pocsuite3.modules.zoomeye import ZoomEye
from pocsuite3.shellcodes import OSShellcodes, WebShell


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
