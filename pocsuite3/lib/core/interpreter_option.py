#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2018/12/26 下午2:53
# @Author  : chenghs
# @File    : interpreter_option.py
from pocsuite3.lib.core.common import is_ipv6_address_format, is_ip_address_format
from pocsuite3.lib.core.exception import PocsuiteValidationException


class Option(object):
    """ Exploit attribute that is set by the end user """

    def __init__(self, default, description="", require=False):
        self.description = description
        self.require = require

        if default:
            self.__set__("", default)
        else:
            self.display_value = ""
            self.value = ""

    def __get__(self, instance, owner):
        return self.value

    # def __getattr__(self, name):
    #     try:
    #         return self[name]
    #     except KeyError:
    #         raise AttributeError(name)

    # def __setattr__(self, name, value):
    #     self[name] = value


class OptIP(Option):
    """ Option IP attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)
        if description == "":
            self.description = "IPv4 or IPv6 address"
        self.type = "IP Address"

    def __set__(self, instance, value):
        if not value or is_ip_address_format(value) or is_ipv6_address_format(value):
            self.value = self.display_value = value
        else:
            raise PocsuiteValidationException("Invalid address. Provided address is not valid IPv4 or IPv6 address.")


class OptPort(Option):
    """ Option Port attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)
        if description == "":
            self.description = "Target HTTP port"
        self.type = "Port"

    def __set__(self, instance, value):
        try:
            value = int(value)

            if 0 <= value <= 65535:  # max port number is 65535
                self.display_value = str(value)
                self.value = value
            else:
                raise PocsuiteValidationException("Invalid option. Port value should be between 0 and 65536.")
        except ValueError:
            raise PocsuiteValidationException("Invalid option. Cannot cast '{}' to integer.".format(value))


class OptBool(Option):
    """ Option Bool attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)

        if default:
            self.display_value = "true"
        else:
            self.display_value = "false"

        self.value = default
        self.type = "Bool"

    def __set__(self, instance, value):
        if isinstance(value,bool):
            self.value = value
            return

        if value.lower() == "true":
            self.value = True
            self.display_value = value
        elif value.lower() == "false":
            self.value = False
            self.display_value = value
        else:
            raise PocsuiteValidationException("Invalid value. It should be true or false.")


class OptInteger(Option):
    """ Option Integer attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)

        self.type = "Integer"

    def __set__(self, instance, value):
        try:
            self.display_value = str(value)
            self.value = int(value)
        except ValueError:
            raise PocsuiteValidationException("Invalid option. Cannot cast '{}' to integer.".format(value))


class OptFloat(Option):
    """ Option Float attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)

        self.type = "Float"

    def __set__(self, instance, value):
        try:
            self.display_value = str(value)
            self.value = float(value)
        except ValueError:
            raise PocsuiteValidationException("Invalid option. Cannot cast '{}' to float.".format(value))


class OptString(Option):
    """ Option String attribute """

    def __init__(self, default, description="", require=False):
        super().__init__(default, description, require)

        self.type = "String"

    def __set__(self, instance, value):
        try:
            self.value = self.display_value = str(value)
        except ValueError:
            raise PocsuiteValidationException("Invalid option. Cannot cast '{}' to string.".format(value))


class OptItems(Option):
    def __init__(self, default, description="", selected="", require=False):
        super().__init__(default, description, require)
        self.selected = selected
        self.type = "Select"
        self.__set__("", selected)

        if description == "":
            self.description = "You can select {} ,default:{}".format(repr(default), self.selected)

    def __set__(self, instance, value):
        # if value not in self.default:
        #     raise PocsuiteValidationException("Cannot set {},you must select {}".format(value, self.default))
        self.value = self.display_value = value


class OptDict():
    def __init__(self, require=False, selected=False, default={}):
        self.default = {}
        b = ""
        for k, v in default.items():
            self.default[k] = v
            b += "{k}:{v}\n".format(k=k, v=v)
        self.selected = selected
        self.require = require
        self.type = "Dict"
        self.__set__("", selected)

        self.description = "{}\nYou can select {} ,default:{}".format(b,
                                                                        repr(self.default.keys()),
                                                                        self.selected)

    def __set__(self, instance, value):
        # if value not in self.default:
        #     raise PocsuiteValidationException("Cannot set {},you must select {}".format(value, self.default))
        # self.value = self.display_value = value
        self.value = self.default[value] if value in self.default else ""
