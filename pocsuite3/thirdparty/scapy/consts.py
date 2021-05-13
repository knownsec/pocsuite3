# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

from sys import platform, maxsize
import platform as platform_lib

LINUX = platform.startswith("linux")
OPENBSD = platform.startswith("openbsd")
FREEBSD = "freebsd" in platform
NETBSD = platform.startswith("netbsd")
DARWIN = platform.startswith("darwin")
SOLARIS = platform.startswith("sunos")
WINDOWS = platform.startswith("win32")
WINDOWS_XP = platform_lib.release() == "XP"
BSD = DARWIN or FREEBSD or OPENBSD or NETBSD
# See https://docs.python.org/3/library/platform.html#cross-platform
IS_64BITS = maxsize > 2**32
# LOOPBACK_NAME moved to conf.loopback_name

from ctypes import sizeof

from pocsuite3.thirdparty.scapy.structures import bpf_program
from pocsuite3.thirdparty.scapy.data import MTU
SIOCGIFFLAGS = 0xc0206911
BPF_BUFFER_LENGTH = MTU

# From net/bpf.h
BIOCIMMEDIATE = 0x80044270
BIOCGSTATS = 0x4008426f
BIOCPROMISC = 0x20004269
BIOCSETIF = 0x8020426c
BIOCSBLEN = 0xc0044266
BIOCGBLEN = 0x40044266
BIOCSETF = 0x80004267 | ((sizeof(bpf_program) & 0x1fff) << 16)
BIOCSDLT = 0x80044278
BIOCSHDRCMPLT = 0x80044275
BIOCGDLT = 0x4004426a
DLT_IEEE802_11_RADIO = 127
