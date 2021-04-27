import time
from pocsuite3.thirdparty.scapy.consts import DARWIN, WINDOWS, LINUX, BSD, SOLARIS

if not WINDOWS:
    from pocsuite3.thirdparty.scapy.arch_init import *
else:
    from pocsuite3.thirdparty.scapy.arch_windows_init import *
from pocsuite3.thirdparty.scapy.sendrecv import sniff
from threading import Thread, Event


class Sniffer(Thread):
    def __init__(self, filter):
        super().__init__()
        self.filter = "host %s" % filter
        self.daemon = True
        self.socket = None
        self.use_pcap = True
        self.is_admin = False

        if WINDOWS:
            iface = []
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.is_admin=True
            for iface_name in sorted(IFACES):
                iface.append(IFACES[iface_name].data['description'])
            self.use_pcap = conf.use_pcap
            self.interface = iface
            self.stop_sniffer = Event()
            self.pcap = None
        else:
            if os.getuid() == 0:
                self.is_admin = True
            from pocsuite3.thirdparty.scapy.core import get_if_list
            self.interface = get_if_list()
            self.use_pcap = conf.use_pcap
            self.stop_sniffer = Event()
            self.pcap = None

    def run(self):
        self.pcap = sniff(iface=self.interface, filter=self.filter, stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        time.sleep(1)
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()
