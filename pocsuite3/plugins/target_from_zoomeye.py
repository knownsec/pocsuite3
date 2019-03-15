from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import ZoomEye
from pocsuite3.api import register_plugin


class TargetFromZoomeye(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init_zoomeye_api(self):
        self.zoomeye = ZoomEye()
        if self.zoomeye.get_resource_info():
            info_msg = "ZoomEeye search limit {0}".format(self.zoomeye.resources)
            logger.info(info_msg)

    def init(self):
        self.init_zoomeye_api()

        info_msg = "[PLUGIN] try fetch targets from zoomeye with dork: {0}".format(conf.dork)
        logger.info(info_msg)
        targets = self.zoomeye.search(conf.dork, conf.max_page, resource=conf.search_type)
        if targets:
            count = 0
            for target in targets:
                if self.add_target(target):
                    count += 1

            info_msg = "[PLUGIN] get {0} target(s) from zoomeye".format(count)
            logger.info(info_msg)


register_plugin(TargetFromZoomeye)
