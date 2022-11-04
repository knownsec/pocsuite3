import{_ as s,j as n,g as a,H as l}from"./chunks/framework.8815fd6f.js";const C=JSON.parse('{"title":"API","description":"","frontmatter":{},"headers":[{"level":2,"title":"General Method","slug":"general-method"},{"level":2,"title":"ShellCode Generation","slug":"shellcode-generation"},{"level":2,"title":"HTTP Service","slug":"http-service"}],"relativePath":"en/guide/poc-api.md","lastUpdated":1658474088000}'),p={name:"en/guide/poc-api.md"},o=l(`<h1 id="api" tabindex="-1">API <a class="header-anchor" href="#api" aria-hidden="true">#</a></h1><p>When writing PoC, please use the API that has been encapsulated by Pocsuite3.</p><h2 id="general-method" tabindex="-1">General Method <a class="header-anchor" href="#general-method" aria-hidden="true">#</a></h2><table><thead><tr><th>Methods</th><th>Instructions</th></tr></thead><tbody><tr><td>from pocsuite3.api import logger</td><td>Log</td></tr><tr><td>from pocsuite3.api import requests</td><td>Patched requests</td></tr><tr><td>from pocsuite3.api import Seebug</td><td>Seebug API</td></tr><tr><td>from pocsuite3.api import ZoomEye</td><td>ZoomEye API</td></tr><tr><td>from pocsuite3.api import Shodan</td><td>Shodan API</td></tr><tr><td>from pocsuite3.api import Fofa</td><td>Fofa API</td></tr><tr><td>from pocsuite3.api import Quake</td><td>Quake API</td></tr><tr><td>from pocsuite3.api import Hunter</td><td>Hunter API</td></tr><tr><td>from pocsuite3.api import Censys</td><td>Censys API</td></tr><tr><td>from pocsuite3.api import CEye</td><td>CEye API</td></tr><tr><td>from pocsuite3.api import Interactsh</td><td>Interactsh API</td></tr><tr><td>from pocsuite3.api import crawl</td><td>Simple crawler</td></tr><tr><td>from pocsuite3.api import PHTTPServer</td><td>Http Service</td></tr><tr><td>from pocsuite3.api import REVERSE_PAYLOAD</td><td>Reverse shell payload</td></tr><tr><td>from pocsuite3.api import get_results</td><td>Get Results</td></tr></tbody></table><p>(TODO: Improve API documentation)</p><h2 id="shellcode-generation" tabindex="-1">ShellCode Generation <a class="header-anchor" href="#shellcode-generation" aria-hidden="true">#</a></h2><p>In some special Linux and Windows environments, it is difficult to get the reverse shell. To overcome this, we have made shellcode for Windows/Linux x86/x64 environment.</p><p>Demo Poc: <a href="https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/thinkphp_rce2.py" target="_blank" rel="noreferrer">https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/thinkphp_rce2.py</a></p><div class="language-python"><span class="copy"></span><pre><code><span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> generate_shellcode_list</span></span>
<span class="line"><span style="color:#A6ACCD;">_list </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">generate_shellcode_list</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">listener_ip</span><span style="color:#89DDFF;">=</span><span style="color:#82AAFF;">get_listener_ip</span><span style="color:#89DDFF;">(),</span><span style="color:#82AAFF;"> </span><span style="color:#A6ACCD;">listener_port</span><span style="color:#89DDFF;">=</span><span style="color:#82AAFF;">get_listener_port</span><span style="color:#89DDFF;">(),</span><span style="color:#82AAFF;"> </span><span style="color:#A6ACCD;">os_target</span><span style="color:#89DDFF;">=</span><span style="color:#82AAFF;">OS</span><span style="color:#89DDFF;">.</span><span style="color:#F07178;">LINUX</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#A6ACCD;">os_target_arch</span><span style="color:#89DDFF;">=</span><span style="color:#82AAFF;">OS_ARCH</span><span style="color:#89DDFF;">.</span><span style="color:#F07178;">X86</span><span style="color:#89DDFF;">)</span></span>
<span class="line"></span></code></pre></div><h2 id="http-service" tabindex="-1">HTTP Service <a class="header-anchor" href="#http-service" aria-hidden="true">#</a></h2><p>For some vulnerabilities that require HTTP services, Pocsuite3 also provides corresponding APIs to support opening an HTTP service locally for verification.</p><p>Test cases can be viewed: <a href="https://github.com/knownsec/pocsuite3/blob/master/tests/test_httpserver.py" target="_blank" rel="noreferrer">https://github.com/knownsec/pocsuite3/blob/master/tests/test_httpserver.py</a></p><div class="language-python"><span class="copy"></span><pre><code><span class="line"><span style="color:#89DDFF;font-style:italic;">&quot;&quot;&quot;</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">If you have issues about development, please read:</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">for more about information, plz visit https://pocsuite.org</span></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">&quot;&quot;&quot;</span></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> http</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">server </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> SimpleHTTPRequestHandler</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> Output</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> POCBase</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> register_poc</span></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> PHTTPServer</span></span>
<span class="line"></span>
<span class="line"></span>
<span class="line"><span style="color:#C792EA;">class</span><span style="color:#A6ACCD;"> </span><span style="color:#FFCB6B;">MyRequestHandler</span><span style="color:#89DDFF;">(</span><span style="color:#FFCB6B;">SimpleHTTPRequestHandler</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#C792EA;">def</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">do_GET</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">self</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">        path </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> self</span><span style="color:#89DDFF;">.</span><span style="color:#F07178;">path</span></span>
<span class="line"><span style="color:#A6ACCD;">        status </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">404</span></span>
<span class="line"><span style="color:#A6ACCD;">        count </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">0</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">        xxe_dtd </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;&#39;</span><span style="color:#C3E88D;">xxx</span><span style="color:#89DDFF;">&#39;&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">if</span><span style="color:#A6ACCD;"> path </span><span style="color:#89DDFF;">==</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">/xxe_dtd</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">            count </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">len</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">xxe_dtd</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">            status </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">200</span></span>
<span class="line"><span style="color:#A6ACCD;">            self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_response</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">status</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">            self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">Content-Type</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">text/html</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">            self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">Content-Length</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">{}</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">format</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">count</span><span style="color:#89DDFF;">))</span></span>
<span class="line"><span style="color:#A6ACCD;">            self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">end_headers</span><span style="color:#89DDFF;">()</span></span>
<span class="line"><span style="color:#A6ACCD;">            self</span><span style="color:#89DDFF;">.</span><span style="color:#F07178;">wfile</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">write</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">xxe_dtd</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">encode</span><span style="color:#89DDFF;">())</span></span>
<span class="line"><span style="color:#A6ACCD;">            </span><span style="color:#89DDFF;font-style:italic;">return</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_response</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">status</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">Content-Type</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">text/html</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">Content-Length</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">{}</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">format</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">count</span><span style="color:#89DDFF;">))</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">end_headers</span><span style="color:#89DDFF;">()</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#C792EA;">def</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">do_HEAD</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">self</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">        status </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">404</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">if</span><span style="color:#A6ACCD;"> self</span><span style="color:#89DDFF;">.</span><span style="color:#F07178;">path</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">endswith</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">jar</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">            status </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#F78C6C;">200</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_response</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">status</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">Content-type</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">text/html</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">send_header</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">Content-Length</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#82AAFF;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">0</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">end_headers</span><span style="color:#89DDFF;">()</span></span>
<span class="line"></span>
<span class="line"></span>
<span class="line"><span style="color:#C792EA;">class</span><span style="color:#A6ACCD;"> </span><span style="color:#FFCB6B;">DemoPOC</span><span style="color:#89DDFF;">(</span><span style="color:#FFCB6B;">POCBase</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">    vulID </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span><span style="color:#A6ACCD;">  </span><span style="color:#676E95;font-style:italic;"># ssvid</span></span>
<span class="line"><span style="color:#A6ACCD;">    version </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">1.0</span><span style="color:#89DDFF;">&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    author </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">seebug</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">]</span></span>
<span class="line"><span style="color:#A6ACCD;">    vulDate </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">2018-03-08</span><span style="color:#89DDFF;">&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    createDate </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">2018-04-12</span><span style="color:#89DDFF;">&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    updateDate </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">2018-04-13</span><span style="color:#89DDFF;">&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    references </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[</span><span style="color:#89DDFF;">&#39;&#39;</span><span style="color:#89DDFF;">]</span></span>
<span class="line"><span style="color:#A6ACCD;">    name </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    appPowerLink </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    appName </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    appVersion </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    vulType </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    desc </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;&#39;&#39;</span></span>
<span class="line"><span style="color:#C3E88D;">    </span><span style="color:#89DDFF;">&#39;&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">    samples </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[]</span></span>
<span class="line"><span style="color:#A6ACCD;">    install_requires </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[</span><span style="color:#89DDFF;">&#39;&#39;</span><span style="color:#89DDFF;">]</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#C792EA;">def</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">_verify</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">self</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">        result </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">{}</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">&#39;&#39;&#39;</span><span style="color:#676E95;font-style:italic;">Simple http server demo</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           default params:</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           		bind_ip=&#39;0.0.0.0&#39;</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           		bind_port=666</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           		is_ipv6=False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           		use_https=False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           		certfile=os.path.join(paths.POCSUITE_DATA_PATH, &#39;cacert.pem&#39;)</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">                requestHandler=BaseRequestHandler</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">           You can write your own handler, default list current directory</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">        </span><span style="color:#89DDFF;font-style:italic;">&#39;&#39;&#39;</span></span>
<span class="line"><span style="color:#A6ACCD;">        httpd </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">PHTTPServer</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">requestHandler</span><span style="color:#89DDFF;">=</span><span style="color:#82AAFF;">MyRequestHandler</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        httpd</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">start</span><span style="color:#89DDFF;">()</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#676E95;font-style:italic;"># Write your code</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">return</span><span style="color:#A6ACCD;"> self</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">parse_output</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">result</span><span style="color:#89DDFF;">)</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#C792EA;">def</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">parse_output</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">self</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> result</span><span style="color:#89DDFF;">):</span></span>
<span class="line"><span style="color:#A6ACCD;">        output </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">Output</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">self</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">if</span><span style="color:#A6ACCD;"> result</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">            output</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">success</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">result</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">else</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">            output</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">fail</span><span style="color:#89DDFF;">(</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">target is not vulnerable</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;font-style:italic;">return</span><span style="color:#A6ACCD;"> output</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">    _attack </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> _verify</span></span>
<span class="line"></span>
<span class="line"></span>
<span class="line"><span style="color:#82AAFF;">register_poc</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">DemoPOC</span><span style="color:#89DDFF;">)</span></span>
<span class="line"></span>
<span class="line"></span></code></pre></div>`,13),e=[o];function t(r,c,D,F,y,A){return a(),n("div",null,e)}var d=s(p,[["render",t]]);export{C as __pageData,d as default};