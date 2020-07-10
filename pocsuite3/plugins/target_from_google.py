from urllib.parse import urlparse
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import conf
from pocsuite3.api import Google
from pocsuite3.api import register_plugin
from pocsuite3.api import kb
from pocsuite3.lib.core.exception import PocsuitePluginDorkException

# 环境配置:
#   本地配置chrome的headless，执行如下命令:
#   headless mode (chrome version >= 59):
#   $ google-chrome --headless --disable-gpu --remote-debugging-port=9222

#   或者直接使用docker
#   $ docker pull fate0/headless-chrome
#   $ docker run -it --rm --cap-add=SYS_ADMIN -p9222:9222 fate0/headless-chrome

#   PS: 需要proxy的时候打开全局就好了
#   

# 使用说明:
#   对目标使用搜索dork语法，程序会返回抓取的域名
#   python  pocsuite3/cli.py -r pocsuite3/pocs/CVE-2020-5902.py --dork-google 'intitle:"BIG-IP" inurl:"tmui"' --thread 10
#   默认对域名做了去重输出，根据需要可以修改script

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
