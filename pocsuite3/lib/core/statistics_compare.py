from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.datatype import AttribDict


class StatisticsCompare(object):

    def __init__(self):
        self.data = {}

    def add_ip(self, ip, source, honeyjar=False):
        if ip not in self.data:
            self.data[ip] = {
                "source": [],
                "honeyjar": honeyjar
            }
        self.data[ip]["source"].append(source)
