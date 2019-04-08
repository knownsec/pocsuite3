# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import re
import socket

from .tools import exec_cmd, hex2dotted, minimal_logger

Log = minimal_logger(__name__)


#: These will always be present for each device (even if they are None)
DEVICE_PROPERTY_DEFAULTS = {
    'inet': None,
    'inet4': "LIST",
    'ether': None,
    'inet6': "LIST",  # Because lists are mutable
    'netmask': None,
}


class Parser(object):
    """
    Main parser class interface
    """
    def __init__(self, ifconfig=None):
        self._interfaces = {}
        self.ifconfig_data = ifconfig
        self.parse(self.ifconfig_data)

    def add_device(self, device_name):
        if device_name in self._interfaces:
            raise RuntimeError("Device {} already added".format(device_name))
        self._interfaces[device_name] = {}
        for key, value in DEVICE_PROPERTY_DEFAULTS.items():
            if value == "LIST":
                self._interfaces[device_name][key] = []
            else:
                self._interfaces[device_name][key] = value

    def parse(self, ifconfig=None):  # noqa: max-complexity=12
        """
        Parse ifconfig output into self._interfaces.

        Optional Arguments:

            ifconfig
                The data (stdout) from the ifconfig command.  Default is to
                call exec_cmd(self.get_command()).

        """
        if not ifconfig:
            ifconfig, __, __ = exec_cmd(self.get_command())
        self.ifconfig_data = ifconfig
        cur = None
        patterns = self.get_patterns()
        for line in self.ifconfig_data.splitlines():
            for pattern in patterns:
                m = re.match(pattern, line)
                if not m:
                    continue
                groupdict = m.groupdict()
                # Special treatment to trigger which interface we're
                # setting for if 'device' is in the line.  Presumably the
                # device of the interface is within the first line of the
                # device block.
                if 'device' in groupdict:
                    cur = groupdict['device']
                    self.add_device(cur)
                elif cur is None:
                    raise RuntimeError(
                        "Got results that don't belong to a device"
                    )

                for k, v in groupdict.items():
                    if k in self._interfaces[cur]:
                        if self._interfaces[cur][k] is None:
                            self._interfaces[cur][k] = v
                        elif hasattr(self._interfaces[cur][k], 'append'):
                            self._interfaces[cur][k].append(v)
                        elif self._interfaces[cur][k] == v:
                            # Silently ignore if the it's the same value as last. Example: Multiple
                            # inet4 addresses, result in multiple netmasks. Cardinality mismatch
                            continue
                        else:
                            raise RuntimeError(
                                "Tried to add {}={} multiple times to {}, it was already: {}".format(
                                    k,
                                    v,
                                    cur,
                                    self._interfaces[cur][k]
                                )
                            )
                    else:
                        self._interfaces[cur][k] = v

        # Copy the first 'inet4' ip address to 'inet' for backwards compatibility
        for device, device_dict in self._interfaces.items():
            if len(device_dict['inet4']) > 0:
                device_dict['inet'] = device_dict['inet4'][0]

        # fix it up
        self._interfaces = self.alter(self._interfaces)

    def alter(self, interfaces):
        """
        Used to provide the ability to alter the interfaces dictionary before
        it is returned from self.parse().

        Required Arguments:

            interfaces
                The interfaces dictionary.

        Returns: interfaces dict

        """
        # fixup some things
        for device, device_dict in interfaces.items():
            if len(device_dict['inet4']) > 0:
                device_dict['inet'] = device_dict['inet4'][0]
            if 'inet' in device_dict and not device_dict['inet'] is None:
                try:
                    host = socket.gethostbyaddr(device_dict['inet'])[0]
                    interfaces[device]['hostname'] = host
                except (socket.herror, socket.gaierror):
                    interfaces[device]['hostname'] = None

            # To be sure that hex values and similar are always consistent, we
            # return everything in lowercase. For instance, Windows writes
            # MACs in upper-case.
            for key, device_item in device_dict.items():
                if hasattr(device_item, 'lower'):
                    interfaces[device][key] = device_dict[key].lower()

        return interfaces

    @classmethod
    def get_command(cls):
        raise NotImplementedError()

    @classmethod
    def get_patterns(cls):
        raise NotImplementedError()

    @property
    def interfaces(self):
        raise NotImplementedError()

    @property
    def default_interface(self):
        raise NotImplementedError()


class NullParser(Parser):
    """
    Doesn't do anything, useful to maintain internal interfaces in case we
    don't want to do anything (because we haven't determined the OS)
    """

    def __init__(self, ifconfig=None):
        self._interfaces = {}
        self.ifconfig_data = ifconfig

    def parse(self, ifconfig=None):
        raise NotImplementedError()

    @property
    def interfaces(self):
        return []

    @property
    def default_interface(self):
        return None


class WindowsParser(Parser):

    @classmethod
    def get_command(cls):
        return 'ipconfig /all'

    @classmethod
    def get_patterns(cls):
        return [
            r"(?P<device>\w.+):",
            r".*?(?:Physical Address|物理地址).*?(?P<ether>[ABCDEFabcdef\d-]+)",
            r".*?IPv4.*?(?P<inet4>(?:(?:\d+\.){3}\d+))",
            r".*?IPv6.*?(?P<inet6>(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(?::[a-f0-9]{1,4}){0,7}%?[a-z0-9]*))",
        ]

    @property
    def interfaces(self):
        """
        Returns the full interfaces dictionary.

        """
        return self._interfaces

    def alter(self, interfaces):
        interfaces = Parser.alter(self, interfaces)
        # fixup some things
        for device, device_dict in interfaces.items():
            if 'ether' in device_dict and interfaces[device]['ether']:
                interfaces[device]['ether'] = device_dict['ether'].replace('-', ':')
        return interfaces


class UnixParser(Parser):

    @classmethod
    def get_command(cls):
        ifconfig_cmd = 'ifconfig'
        for path in ['/sbin', '/usr/sbin', '/bin', '/usr/bin']:
            if os.path.exists(os.path.join(path, ifconfig_cmd)):
                ifconfig_cmd = os.path.join(path, ifconfig_cmd)
                break
        ifconfig_cmd = ifconfig_cmd + " -a"
        return ifconfig_cmd

    @classmethod
    def get_patterns(cls):
        return [
            '(?P<device>^[-a-zA-Z0-9:]+): flags=(?P<flags>.*) mtu (?P<mtu>.*)',
            '.*inet\s+(?P<inet4>[\d\.]+).*',
            '.*inet6\s+(?P<inet6>[\d\:abcdef]+).*',
            '.*broadcast (?P<broadcast>[^\s]*).*',
            '.*netmask (?P<netmask>[^\s]*).*',
            '.*ether (?P<ether>[^\s]*).*',
        ]

    @property
    def interfaces(self):
        """
        Returns the full interfaces dictionary.

        """
        return self._interfaces

    def _default_interface(self, route_output=None):
        """
        :param route_output: For mocking actual output
        """
        if not route_output:
            out, __, __ = exec_cmd('/sbin/route -n')
            lines = out.splitlines()
        else:
            lines = route_output.split("\n")

        for line in lines[2:]:
            line = line.split()
            if '0.0.0.0' in line and \
               'UG' in line:
                iface = line[-1]
                return self.interfaces.get(iface, None)

    @property
    def default_interface(self):
        """
        Returns the default interface device.
        """
        return self._default_interface()


class LinuxParser(UnixParser):

    @classmethod
    def get_patterns(cls):
        return super(LinuxParser, cls).get_patterns() + [
            '(?P<device>^[a-zA-Z0-9:_-]+)(.*)Link encap:(.*).*',
            '(.*)Link encap:(.*)(HWaddr )(?P<ether>[^\s]*).*',
            '.*(inet addr:\s*)(?P<inet4>[^\s]+).*',
            '.*(inet6 addr:\s*)(?P<inet6>[^\s\/]+)',
            '.*(P-t-P:)(?P<ptp>[^\s]*).*',
            '.*(Bcast:)(?P<broadcast>[^\s]*).*',
            '.*(Mask:)(?P<netmask>[^\s]*).*',
            '.*(RX bytes:)(?P<rxbytes>\d+).*',
            '.*(TX bytes:)(?P<txbytes>\d+).*',
        ]

    def alter(self, interfaces):
        return interfaces


class UnixIPParser(UnixParser):
    """
    Because ifconfig is getting deprecated, we can use ip address instead
    """

    @classmethod
    def get_command(cls):
        ifconfig_cmd = 'ip'
        for path in ['/sbin', '/usr/sbin', '/bin', '/usr/bin']:
            if os.path.exists(os.path.join(path, ifconfig_cmd)):
                ifconfig_cmd = os.path.join(path, ifconfig_cmd)
                break
        ifconfig_cmd = ifconfig_cmd + " address show"
        return ifconfig_cmd

    @classmethod
    def get_patterns(cls):
        return [
            '\s*[0-9]+:\s+(?P<device>[a-zA-Z0-9]+):.*mtu (?P<mtu>.*)',
            '.*(inet\s)(?P<inet4>[\d\.]+)',
            '.*(inet6 )(?P<inet6>[^/]*).*',
            '.*(ether )(?P<ether>[^\s]*).*',
            '.*inet\s.*(brd )(?P<broadcast>[^\s]*).*',
            '.*(inet )[^/]+(?P<netmask>[/][0-9]+).*',
        ]

    def _default_interface(self, route_output=None):
        """
        :param route_output: For mocking actual output
        """
        if not route_output:
            out, __, __ = exec_cmd('/sbin/ip route')
            lines = out.splitlines()
        else:
            lines = route_output.split("\n")

        for line in lines:
            line = line.split()
            if 'default' in line:
                iface = line[4]
                return self.interfaces.get(iface, None)

    @property
    def default_interface(self):
        """
        Returns the default interface device.
        """
        return self._default_interface()



class MacOSXParser(UnixParser):

    @classmethod
    def get_patterns(cls):
        return super(MacOSXParser, cls).get_patterns() + [
            '.*(status: )(?P<status>[^\s]*).*',
            '.*(media: )(?P<media>.*)',
        ]

    def alter(self, interfaces):
        interfaces = super(MacOSXParser, self).alter(interfaces)
        # fix up netmask address for mac
        for device, device_dict in interfaces.items():
            if device_dict['netmask'] is not None:
                interfaces[device]['netmask'] = hex2dotted(device_dict['netmask'])
        return interfaces

    def _default_interface(self, route_output=None):
        """
        :param route_output: For mocking actual output
        """
        if not route_output:
            out, __, __ = exec_cmd('/usr/sbin/netstat -rn -f inet')
            lines = out.splitlines()
        else:
            lines = route_output.split("\n")

        for line in lines:
            line = line.split()
            if 'default' in line:
                iface = line[-1]
                return self.interfaces.get(iface, None)

    @property
    def default_interface(self):
        """
        Returns the default interface device.
        """
        return self._default_interface()
