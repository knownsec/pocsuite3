import time

from pocsuite3.lib.core.common import get_local_ip, desensitization, data_to_stdout
from pocsuite3.thirdparty.scapy.consts import DARWIN, WINDOWS, LINUX, BSD, SOLARIS
from pocsuite3.lib.core.data import logger
if not WINDOWS:
    from pocsuite3.thirdparty.scapy.arch_init import *
else:
    from pocsuite3.thirdparty.scapy.arch_windows_init import *
from pocsuite3.thirdparty.scapy.sendrecv import sniff, AsyncSniffer
from threading import Thread, Event


class Sniffer(Thread):
    def __init__(self, filter):
        super().__init__()
        self.filter = "host %s" % filter
        self.daemon = True
        self.socket = None
        self.use_pcap = True
        self.is_admin = False
        logger.info("Local network adapter information, choose a network you want to capture")
        if WINDOWS:
            iface = []
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.is_admin = True
            ips = get_local_ip(all=True)
            message = '----- Local IP Address -----\n'
            name = []
            interface_ips = []
            for iface_name in sorted(IFACES):
                if list(set(IFACES[iface_name].data['ips'])):
                    if list(set(IFACES[iface_name].data['ips']))[0] in ips:
                        name.append(IFACES[iface_name].data['name'])
                        interface_ips.append(list(set(IFACES[iface_name].data['ips']))[0])
                        iface.append(IFACES[iface_name].data['description'])
            for i, ip in enumerate(interface_ips):
                message += "{0}   {1}    {2}\n".format(i, name[i], ip)
        else:
            if os.getuid() == 0:
                self.is_admin = True
            from pocsuite3.thirdparty.scapy.core import get_if_list,get_if_lists
            iface, ips = get_if_lists()
            message = '----- Local IP Address -----\n'
            for i, ip in enumerate(ips):
                message += "{0}   {1}    {2}\n".format(i, iface[i], ip)
        data_to_stdout(message)
        choose = input('Choose>: ').strip()
        self.interface = iface[int(choose)]
        self.use_pcap = conf.use_pcap
        self.stop_sniffer = Event()
        self.pcap = None

    def run(self):
        self.pcap = AsyncSniffer()
        #In order to ensure that all packets can be captured, a adapter must be specified. If it is all adapters, it will lost the data package
        self.pcap._run(iface=self.interface, filter=self.filter)

    def join(self, timeout=None):
        self.pcap.continue_sniff = False
        super().join(timeout)
