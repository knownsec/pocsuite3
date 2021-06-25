# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Main module for interactive startup.
"""

# from __future__ import absolute_import
# from __future__ import print_function


import importlib
from pocsuite3.thirdparty.scapy.error import log_interactive
import pocsuite3.thirdparty.scapy.six as six
from pocsuite3.thirdparty.scapy.compat import Any, Dict, List, Optional

IGNORED = list(six.moves.builtins.__dict__)

LAYER_ALIASES = {
    "tls": "tls.all"
}


def _validate_local(x):
    # type: (str) -> bool
    """Returns whether or not a variable should be imported.
    Will return False for any default modules (sys), or if
    they are detected as private vars (starting with a _)"""
    global IGNORED
    return x[0] != "_" and x not in IGNORED



######################
#  Extension system  #
######################


def _load(module, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Python module to make variables, objects and functions
available globally.

    The idea is to load the module using importlib, then copy the
symbols to the global symbol table.

    """
    if globals_dict is None:
        globals_dict = six.moves.builtins.__dict__
    try:
        mod = importlib.import_module(module)
        if '__all__' in mod.__dict__:
            # import listed symbols
            for name in mod.__dict__['__all__']:
                if symb_list is not None:
                    symb_list.append(name)
                globals_dict[name] = mod.__dict__[name]
        else:
            # only import non-private symbols
            for name, sym in six.iteritems(mod.__dict__):
                if _validate_local(name):
                    if symb_list is not None:
                        symb_list.append(name)
                    globals_dict[name] = sym
    except Exception:
        log_interactive.error("Loading module %s", module, exc_info=True)


def load_module(name, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Scapy module to make variables, objects and functions
    available globally.

    """
    _load("scapy.modules." + name,
          globals_dict=globals_dict, symb_list=symb_list)


def load_layer(name, globals_dict=None, symb_list=None):
    # type: (str, Optional[Dict[str, Any]], Optional[List[str]]) -> None
    """Loads a Scapy layer module to make variables, objects and functions
    available globally.

    """
    _load("scapy.layers." + LAYER_ALIASES.get(name, name),
          globals_dict=globals_dict, symb_list=symb_list)

