from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import ZoomEye
from pocsuite3.api import register_plugin
from pocsuite3.api import kb
from pocsuite3.lib.core.exception import PocsuitePluginDorkException


class TargetFromZoomeye(PluginBase):
    category = PLUGIN_TYPE.TARGETS

    def init_zoomeye_api(self):
        self.zoomeye = ZoomEye(username=conf.login_user, password=conf.login_pass)
        if self.zoomeye.get_resource_info():
            info_msg = "[PLUGIN] ZoomEeye search limit {0}".format(self.zoomeye.resources)
            logger.info(info_msg)
        else:
            info_msg = "[PLUGIN] ZoomEye login faild"
            logger.error(info_msg)

    def init(self):
        self.init_zoomeye_api()
        dork = None
        if conf.dork_zoomeye:
            dork = conf.dork_zoomeye
        else:
            dork = conf.dork
        if not dork:
            msg = "Need to set up dork (please --dork or --dork-zoomeye)"
            raise PocsuitePluginDorkException(msg)
        if conf.dork_b64:
            import base64
            dork = str(base64.b64decode(dork),encoding = "utf-8")

        info_msg = "[PLUGIN] try fetch targets from zoomeye with dork: {0}".format(dork)
        logger.info(info_msg)
        targets = self.zoomeye.search(dork, conf.max_page, resource=conf.search_type)
        count = 0
        if targets:
            for target in targets:
                if self.add_target(target):
                    count += 1

        info_msg = "[PLUGIN] get {0} target(s) from zoomeye".format(count)
        logger.info(info_msg)


register_plugin(TargetFromZoomeye)
