# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Operating system specific functionality.
"""

# from __future__ import absolute_import
import socket

from pocsuite3.thirdparty.scapy.consts import LINUX, SOLARIS, WINDOWS, BSD
from pocsuite3.thirdparty.scapy.config import conf, _set_conf_sockets
from pocsuite3.thirdparty.scapy.data import IPV6_ADDR_GLOBAL
from pocsuite3.thirdparty.scapy.compat import orb
from pocsuite3.thirdparty.scapy.pton_ntop import inet_ntop, inet_pton
conf.use_pcap = True

def str2mac(s):
    return ("%02x:" * 6)[:-1] % tuple(orb(x) for x in s)


if not WINDOWS:
    if not conf.use_pcap:
        from pocsuite3.thirdparty.scapy.core import get_if_raw_addr


def get_if_addr(iff):
    return inet_ntop(socket.AF_INET, get_if_raw_addr(iff))


if LINUX:
    from pocsuite3.thirdparty.scapy.linux import *  # noqa F403
elif BSD:
    from pocsuite3.thirdparty.scapy.unix import read_routes, read_routes6, in6_getifaddr  # noqa: F401, E501
    from pocsuite3.thirdparty.scapy.core import *  # noqa F403
    if not conf.use_pcap:
        # Native
        from pocsuite3.thirdparty.scapy.supersocket import * # noqa F403
        conf.use_bpf = True
elif SOLARIS:
    from pocsuite3.thirdparty.scapy.solaris import *  # noqa F403
elif WINDOWS:
    from pocsuite3.thirdparty.scapy.arch_windows_init import *  # noqa F403
    from pocsuite3.thirdparty.scapy.native import *  # noqa F403

if conf.iface is None:
    conf.iface = conf.loopback_name

_set_conf_sockets()  # Apply config


def get_if_addr6(iff):
    """
    Returns the main global unicast address associated with provided
    interface, in human readable form. If no global address is found,
    None is returned.
    """
    return next((x[0] for x in in6_getifaddr()
                 if x[2] == iff and x[1] == IPV6_ADDR_GLOBAL), None)


def get_if_raw_addr6(iff):
    """
    Returns the main global unicast address associated with provided
    interface, in network format. If no global address is found, None
    is returned.
    """
    ip6 = get_if_addr6(iff)
    if ip6 is not None:
        return inet_pton(socket.AF_INET6, ip6)

    return None
