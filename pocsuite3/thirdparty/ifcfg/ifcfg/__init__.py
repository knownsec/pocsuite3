# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import platform
from . import tools
from . import parser

__version__ = "0.17"

Log = tools.minimal_logger(__name__)


#: Module instance properties, can be mocked for testing
distro = platform.system()


def get_parser_class():
    """
    Returns the parser according to the system platform
    """
    global distro
    if distro == 'Linux' or 'CYGWIN' in distro:
        Parser = parser.LinuxParser
        if not os.path.exists(Parser.get_command()[0]):
            Parser = parser.UnixIPParser
    elif distro in ['Darwin', 'MacOSX']:
        Parser = parser.MacOSXParser
    elif distro == 'Windows':
        # For some strange reason, Windows will always be win32, see:
        # https://stackoverflow.com/a/2145582/405682
        Parser = parser.WindowsParser
    else:
        Parser = parser.NullParser
        Log.error("Unknown distro type '%s'." % distro)
    Log.debug("Distro detected as '%s'" % distro)
    Log.debug("Using '%s'" % Parser)

    return Parser


#: Module instance properties, can be mocked for testing
Parser = get_parser_class()


def get_parser(ifconfig=None):
    """
    Detect the proper parser class, and return it instantiated.

    Optional Arguments:

        ifconfig
            The ifconfig (stdout) to pass to the parser (used for testing).

    """
    global Parser
    return Parser(ifconfig=ifconfig)


def interfaces(ifconfig=None):
    """
    Return just the parsed interfaces dictionary from the proper parser.

    """
    global Parser
    return Parser(ifconfig=ifconfig).interfaces


def default_interface(ifconfig=None, route_output=None):
    """
    Return just the default interface device dictionary.

    :param ifconfig: For mocking actual command output
    :param route_output: For mocking actual command output
    """
    global Parser
    return Parser(ifconfig=ifconfig)._default_interface(route_output=route_output)
