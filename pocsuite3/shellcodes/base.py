

class ShellCode:
    def __init__(self, os_target='', os_target_arch='', connect_back_ip='localhost', connect_back_port=5555,
                 bad_chars=[], prefix='', suffix=''):
        self.os_target = os_target
        self.os_target_arch = os_target_arch
        self.connect_back_ip = connect_back_ip
        self.connect_back_port = connect_back_port
        self.bad_chars = bad_chars
        self.prefix = prefix
        self.suffix = suffix
        self.name = ''

    def format_shellcode(self, code):
        if isinstance(code, str):
            code = code.replace('{{LOCALHOST}}', self.connect_back_ip)
            code = code.replace('{{LOCALPORT}}', str(self.connect_back_port))

        return code

    def get_shellcode(self, inline=False):
        return ''

    def make_inline(self, payload):
        payload = payload.replace('\t', ' ')
        payload = payload.replace('\r', ' ')
        payload = payload.replace('\n', ' ')
        return payload
