from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Shodan
from pocsuite3.api import register_plugin


class TargetFromShodan(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init_shodan_api(self):
        self.shodan = Shodan()
        if self.shodan.get_resource_info():
            info_msg = "shodan credits limit {0}".format(self.shodan.credits)
            logger.info(info_msg)

    def init(self):
        self.init_shodan_api()

        info_msg = "[PLUGIN] try fetch targets from shodan with dork: {0}".format(conf.dork)
        logger.info(info_msg)
        targets = self.shodan.search(conf.dork, conf.max_page, resource=conf.search_type)
        if targets:
            count = 0
            for target in targets:
                if self.add_target(target):
                    count += 1

            info_msg = "[PLUGIN] get {0} target(s) from shodan".format(count)
            logger.info(info_msg)


register_plugin(TargetFromShodan)
