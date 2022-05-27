<%@ page import="java.util.*,java.io.*" %>
<%@ page import="java.io.*"%>
<% 
String str = request.getParameter("str");
String str1 = str.substring(0,30);
out.println(str1);
String path = application.getRealPath(request.getRequestURI());
out.println(path);
File d=new File(path);
if(d.exists()){d.delete();}
%>