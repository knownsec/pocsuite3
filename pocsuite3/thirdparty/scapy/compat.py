# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Python 2 and 3 link classes.
"""

# from __future__ import absolute_import
import base64
import binascii
import gzip
import struct
import sys

import pocsuite3.thirdparty.scapy.six as six

###########
# Python3 #
###########


def lambda_tuple_converter(func):
    """
    Converts a Python 2 function as
      lambda (x,y): x + y
    In the Python 3 format:
      lambda x,y : x + y
    """
    if func is not None and func.__code__.co_argcount == 1:
        return lambda *args: func(args[0] if len(args) == 1 else args)
    else:
        return func

def raw(x):
    """Builds a packet and returns its bytes representation.
    This function is and always be cross-version compatible"""
    return bytes(x)

def bytes_encode(x):
    """Ensure that the given object is bytes.
    If the parameter is a packet, raw() should be preferred.
    """
    if isinstance(x, str):
        return x.encode()
    return bytes(x)

if sys.version_info[0:2] <= (3, 4):
    def plain_str(x):
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode(errors="ignore")
        return str(x)
else:
    # Python 3.5+
    def plain_str(x):
        """Convert basic byte objects to str"""
        if isinstance(x, bytes):
            return x.decode(errors="backslashreplace")
        return str(x)

def chb(x):
    """Same than chr() but encode as bytes."""
    return struct.pack("!B", x)

def orb(x):
    """Return ord(x) when not already an int."""
    if isinstance(x, int):
        return x
    return ord(x)


def bytes_hex(x):
    """Hexify a str or a bytes object"""
    return binascii.b2a_hex(bytes_encode(x))


def hex_bytes(x):
    """De-hexify a str or a byte object"""
    return binascii.a2b_hex(bytes_encode(x))


def base64_bytes(x):
    """Turn base64 into bytes"""
    return base64.decodebytes(bytes_encode(x))


def bytes_base64(x):
    """Turn bytes into base64"""
    return base64.encodebytes(bytes_encode(x)).replace(b'\n', b'')


gzip_decompress = gzip.decompress
gzip_compress = gzip.compress

# Typing compatibility

try:
    # Only required if using mypy-lang for static typing
    from typing import Optional, List, Union, Callable, Any, AnyStr, Tuple, \
        Sized, Dict, Pattern, cast
except ImportError:
    # Let's make some fake ones.

    def cast(_type, obj):
        return obj

    class _FakeType(object):
        # make the objects subscriptable indefinetly
        def __getitem__(self, item):
            return _FakeType()

    Optional = _FakeType()
    Union = _FakeType()
    Callable = _FakeType()
    List = _FakeType()
    Dict = _FakeType()
    Any = _FakeType()
    AnyStr = _FakeType()
    Tuple = _FakeType()
    Pattern = _FakeType()

    class Sized(object):
        pass
