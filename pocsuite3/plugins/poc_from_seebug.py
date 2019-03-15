from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Seebug
from pocsuite3.api import register_plugin


class PocFromSeebug(PluginBase):
    category = PLUGIN_TYPE.POCS

    def init_seebug_api(self):
        self.seebug = Seebug()

    def init(self):
        self.init_seebug_api()
        if conf.poc and conf.poc.startswith('ssvid-'):
            poc = self.seebug.fetch_poc(conf.poc)
            if poc and self.add_poc(poc):
                info_msg = "[PLUGIN] load PoC script {0} from seebug success".format(conf.poc)
            else:
                info_msg = "[PLUGIN] load PoC script {0} from seebug failed".format(conf.poc)
            logger.info(info_msg)

        if conf.vul_keyword:
            pocs = self.seebug.search_poc(conf.vul_keyword)
            info_msg = "Found {0} available PoC(s) from Seebug website".format(len(pocs))
            logger.info(info_msg)

            for poc_item in pocs:
                ssvid = str(poc_item['id'])
                poc = self.seebug.fetch_poc(ssvid)
                if poc and self.add_poc(poc):
                    info_msg = "[PLUGIN] load PoC script '{0}' from seebug success".format(poc_item['name'])
                else:
                    info_msg = "[PLUGIN] load PoC script '{0}' from seebug failed".format(poc_item['name'])
                logger.info(info_msg)


register_plugin(PocFromSeebug)
