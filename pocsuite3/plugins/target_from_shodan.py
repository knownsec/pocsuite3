from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Shodan
from pocsuite3.api import register_plugin
from pocsuite3.api import kb
from pocsuite3.lib.core.exception import PocsuitePluginDorkException


class TargetFromShodan(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init_shodan_api(self):
        self.shodan = Shodan(token=conf.shodan_token)
        if self.shodan.get_resource_info():
            info_msg = "[PLUGIN] shodan credits limit {0}".format(self.shodan.credits)
            logger.info(info_msg)

    def init(self):
        self.init_shodan_api()
        dork = None
        if conf.dork_shodan:
            dork = conf.dork_shodan
        else:
            dork = conf.dork
        if not dork:
            msg = "Need to set up dork (please --dork or --dork-shodan)"
            raise PocsuitePluginDorkException(msg)
        if conf.dork_b64:
            import base64
            dork = str(base64.b64decode(dork),encoding = "utf-8")

        if kb.comparison:
            kb.comparison.add_dork("Shodan", dork)
        info_msg = "[PLUGIN] try fetch targets from shodan with dork: {0}".format(dork)
        logger.info(info_msg)
        targets = self.shodan.search(dork, conf.max_page, resource=conf.search_type)
        count = 0
        if targets:
            for target in targets:
                if kb.comparison:
                    kb.comparison.add_ip(target, "Shodan")
                if self.add_target(target):
                    count += 1

        info_msg = "[PLUGIN] get {0} target(s) from shodan".format(count)
        logger.info(info_msg)


register_plugin(TargetFromShodan)
