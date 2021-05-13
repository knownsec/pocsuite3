# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
External link to programs
"""

import os
import subprocess
from pocsuite3.thirdparty.scapy.error import log_loading

# Notice: this file must not be called before scapy_main.py, if started
# in interactive mode, because it needs to be called after the
# logger has been setup, to be able to print the warning messages

# MATPLOTLIB

plt = None
Line2D = None
MATPLOTLIB = 0
MATPLOTLIB_INLINED = 0
MATPLOTLIB_DEFAULT_PLOT_KARGS = dict()


def _test_pyx():
    """Returns if PyX is correctly installed or not"""
    try:
        with open(os.devnull, 'wb') as devnull:
            r = subprocess.check_call(["pdflatex", "--version"],
                                      stdout=devnull, stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        return False
    else:
        return r == 0


try:
    import pyx  # noqa: F401
    if _test_pyx():
        PYX = 1
    else:
        log_loading.info("PyX dependencies are not installed ! Please install TexLive or MikTeX.")  # noqa: E501
        PYX = 0
except ImportError:
    log_loading.info("Can't import PyX. Won't be able to use psdump() or pdfdump().")  # noqa: E501
    PYX = 0
