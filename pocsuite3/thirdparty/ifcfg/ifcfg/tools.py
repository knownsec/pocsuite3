# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import locale
import logging
import os
from subprocess import PIPE, Popen

system_encoding = locale.getpreferredencoding()


def minimal_logger(name):
    log = logging.getLogger(name)
    formatter = logging.Formatter(
        "%(asctime)s IFCFG DEBUG : %(name)s : %(message)s"
    )
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG)

    if 'IFCFG_DEBUG' in os.environ.keys() and os.environ['IFCFG_DEBUG'] == '1':
        log.setLevel(logging.DEBUG)
        log.addHandler(console)
    return log

def exec_cmd(cmd_args):
    # Using `shell=True` because commands may be scripts
    # Using `universal_newlines=False` so we do not choke on implicit decode
    # errors of bytes that are invalid (happens on Windows)
    # NB! Python 2 returns a string, Python 3 returns a bytestring
    # https://github.com/ftao/python-ifcfg/issues/17
    proc = Popen(cmd_args, stdout=PIPE, stderr=PIPE, universal_newlines=False, shell=True)
    stdout, stderr = proc.communicate()
    proc.wait()

    # Decode returned strings according to system encoding
    stdout = stdout.decode(system_encoding, errors='replace')
    stderr = stderr.decode(system_encoding, errors='replace')

    return (stdout, stderr, proc.returncode)

def hex2dotted(hex_num):
    num = hex_num.split('x')[1]
    w = int(num[0:2], 16)
    x = int(num[2:4], 16)
    y = int(num[4:6], 16)
    z = int(num[6:8], 16)

    return "%d.%d.%d.%d" % (w, x, y, z)
