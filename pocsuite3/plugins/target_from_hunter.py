from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Hunter
from pocsuite3.api import register_plugin
from pocsuite3.api import kb
from pocsuite3.lib.core.exception import PocsuitePluginDorkException


class TargetFromHunter(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init_hunter_api(self):
        self.hunter = Hunter(token=conf.hunter_token)
        info_msg = "[PLUGIN] Hunter credits limit {0}".format(self.hunter.credits)
        logger.info(info_msg)

    def init(self):
        self.init_hunter_api()
        dork = None
        if conf.dork_hunter:
            dork = conf.dork_hunter
        else:
            dork = conf.dork
        if not dork:
            msg = "Need to set up dork (please --dork or --dork-hunter)"
            raise PocsuitePluginDorkException(msg)
        if conf.dork_b64:
            import base64
            dork = str(base64.b64decode(dork), encoding="utf-8")

        if kb.comparison:
            kb.comparison.add_dork("Hunter", dork)
        info_msg = "[PLUGIN] try fetch targets from Hunter with dork: {0}".format(dork)
        logger.info(info_msg)
        targets = self.hunter.search(dork, conf.max_page)
        count = 0
        if targets:
            for target in targets:
                if kb.comparison:
                    kb.comparison.add_ip(target, "Hunter")
                if self.add_target(target):
                    count += 1

        info_msg = "[PLUGIN] get {0} target(s) from Hunter".format(count)
        logger.info(info_msg)


register_plugin(TargetFromHunter)
