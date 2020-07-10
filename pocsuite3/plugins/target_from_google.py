from urllib.parse import urlparse
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Google
from pocsuite3.api import register_plugin
from pocsuite3.api import kb
from pocsuite3.lib.core.exception import PocsuitePluginDorkException


class TargetFromGoogle(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init(self):
        self.google = Google()
        dork = None
        if conf.dork_google:
            dork = conf.dork_google
        else:
            dork = conf.dork
        if not dork:
            msg = "Need to set up dork (please --dork or --dork-google)"
            raise PocsuitePluginDorkException(msg)
        if kb.comparison:
            kb.comparison.add_dork("Google", dork)
        info_msg = "[PLUGIN] try fetch targets from google with dork: {0}".format(
            dork)
        logger.info(info_msg)
        targets = self.google.search(dork)
        count = 0
        tmp = []
        if targets:
            for target in targets:
                url = urlparse(target)
                if url.scheme+"://"+url.netloc != 'https://www.google.com':
                    tmp.append(url.scheme+"://"+url.netloc)
            targets = list(set(tmp))
            for target in targets:
                if kb.comparison:
                    kb.comparison.add_ip(target, "Google")
                if self.add_target(target):
                    count += 1

            info_msg = "[PLUGIN] get {0} target(s) from google".format(count)
            logger.info(info_msg)


register_plugin(TargetFromGoogle)
