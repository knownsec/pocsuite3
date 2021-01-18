import re
from collections import OrderedDict

from pocsuite3.api \
    import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE, get_listener_ip, get_listener_port
from pocsuite3.lib.core.interpreter_option \
    import OptString, OptDict, OptIP, OptPort, OptBool, OptInteger, OptFloat, OptItems
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DemoPOC(POCBase):
    vulID = '1571'                  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'                   # 默认为1
    author = 'seebug'               # PoC作者的大名
    vulDate = '2014-10-16'          # 漏洞公开的时间,不知道就写今天
    createDate = '2014-10-16'       # 编写 PoC 的日期
    updateDate = '2014-10-16'       # PoC 更新的时间,默认和编写时间一样
    references = ['https://xxx.xx.com.cn']      # 漏洞地址来源,0day不用写
    name = 'XXXX SQL注入漏洞 PoC'   # PoC 名称
    appPowerLink = 'https://www.drupal.org/'    # 漏洞厂商主页地址
    appName = 'Drupal'          # 漏洞应用名称
    appVersion = '7.x'          # 漏洞影响版本
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS      # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []                # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []       # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = '''
            Drupal 在处理 IN 语句时，展开数组时 key 带入 SQL 语句导致 SQL 注入，
            可以添加管理员、造成信息泄露。
        '''                     # 漏洞简要描述
    pocDesc = ''' 
            poc的用法描述 
        '''                     # POC用法描述

    def _options(self):
        opt = OrderedDict()     # value = self.get_option('key')
        opt["string"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        opt["integer"] = OptInteger('', description='这个poc需要用户密码，请输出用户密码', require=False)
        return opt

    def _verify(self):
        output = Output(self)
        # 验证代码
        result = {
            # 不管是验证模式或者攻击模式，返回结果 result 中的 key 值必须按照下面的规范来写
            # [ PoC结果返回规范 ]( https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md#resultstandard )
            'Result': {
                'DBInfo': {'Username': 'xxx', 'Password': 'xxx', 'Salt': 'xxx', 'Uid': 'xxx', 'Groupid': 'xxx'},
                'ShellInfo': {'URL': 'xxx', 'Content': 'xxx'},
                'FileInfo': {'Filename': 'xxx', 'Content': 'xxx'},
                'XSSInfo': {'URL': 'xxx', 'Payload': 'xxx'},
                'AdminInfo': {'Uid': 'xxx', 'Username': 'xxx', 'Password': 'xxx'},
                'Database': {'Hostname': 'xxx', 'Username': 'xxx', 'Password': 'xxx', 'DBname': 'xxx'},
                'VerifyInfo': {'URL': 'xxx', 'Postdata': 'xxx', 'Path': 'xxx'},
                'SiteAttr': {'Process': 'xxx'},
                'Stdout': 'result output string'
            }
        }
        if result:  # result是返回结果
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        output = Output(self)
        result = {}
        # 攻击代码
        pass

    def _shell(self):
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """
        cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        # 攻击代码 execute cmd
        pass


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(DemoPOC)
