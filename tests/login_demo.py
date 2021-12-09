#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/2/26 2:33 PM
# @Author  : chenghsm
# @File    : login_demo.py
# @Descript: 自定义命令参数登录例子

from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '00000'  # ssvid
    version = '1.0'
    author = ['chenghs']
    vulDate = '2019-2-26'
    createDate = '2019-2-26'
    updateDate = '2019-2-25'
    references = ['']
    name = '自定义命令参数登录例子'
    appPowerLink = 'http://www.knownsec.com/'
    appName = 'test'
    appVersion = 'test'
    vulType = 'demo'
    desc = '''这个例子说明了你可以使用console模式设置一些参数或者使用命令中的'--'来设置自定义的参数'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        o["password"] = OptString('', description='这个poc需要用户密码，请输出用户密码', require=False)
        return o

    def _verify(self):
        result = {}
        payload = "username={0}&password={1}".format(self.get_option("username"), self.get_option("password"))
        r = requests.post(self.url, data=payload)
        if r.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = payload

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
