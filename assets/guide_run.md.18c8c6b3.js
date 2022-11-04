import{_ as s,a,b as n}from"./chunks/run_integration.2000fc07.js";import{_ as p,j as o,g as l,H as e}from"./chunks/framework.8815fd6f.js";const h=JSON.parse('{"title":"\u8FD0\u884C","description":"","frontmatter":{},"headers":[{"level":2,"title":"\u547D\u4EE4\u884C","slug":"\u547D\u4EE4\u884C"},{"level":2,"title":"\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0","slug":"\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0"},{"level":2,"title":"\u96C6\u6210\u8C03\u7528","slug":"\u96C6\u6210\u8C03\u7528"}],"relativePath":"guide/run.md","lastUpdated":1658173066000}'),t={name:"guide/run.md"},c=e('<h1 id="\u8FD0\u884C" tabindex="-1">\u8FD0\u884C <a class="header-anchor" href="#\u8FD0\u884C" aria-hidden="true">#</a></h1><p>Pocsuite3 \u6709\u4E09\u79CD\u8FD0\u884C\u65B9\u6CD5\uFF0C1\u3001\u547D\u4EE4\u884C\uFF1B2\u3001\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0\uFF1B3\u3001\u96C6\u6210\u8C03\u7528\u3002</p><h2 id="\u547D\u4EE4\u884C" tabindex="-1">\u547D\u4EE4\u884C <a class="header-anchor" href="#\u547D\u4EE4\u884C" aria-hidden="true">#</a></h2><p>\u76F4\u63A5\u8FD0\u884C pocsuite \u547D\u4EE4\uFF0C\u5E76\u4F7F\u7528\u5BF9\u5E94\u53C2\u6570\u6307\u5B9A\u5F85\u6D4B\u8BD5\u7684\u76EE\u6807\u548C PoC\u3002</p><p><img src="'+s+'" alt=""></p><p>\u4E5F\u53EF\u4EE5\u5C06\u53C2\u6570\u5B9A\u4E49\u5728 <code>pocsuite3.ini</code> \u6587\u4EF6\u4E2D\uFF0C\u7136\u540E\u4F7F\u7528 <code>pocsuite -c pocsuite.ini</code> \u8FD0\u884C\u3002</p><p>\u914D\u7F6E\u793A\u4F8B\u53EF\u89C1\uFF1A<a href="./parameter-posuite-ini.html">pocsuite.ini \u914D\u7F6E\u6587\u4EF6\u53C2\u6570\u8BF4\u660E</a></p><h2 id="\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0" tabindex="-1">\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0 <a class="header-anchor" href="#\u4EA4\u4E92\u5F0F\u63A7\u5236\u53F0" aria-hidden="true">#</a></h2><p>\u7C7B\u4F3C Metasploit \u7684\u63A7\u5236\u53F0\uFF0C\u4F7F\u7528 <code>poc-console</code> \u547D\u4EE4\u8FDB\u5165\u3002</p><p><img src="'+a+`" alt=""></p><h2 id="\u96C6\u6210\u8C03\u7528" tabindex="-1">\u96C6\u6210\u8C03\u7528 <a class="header-anchor" href="#\u96C6\u6210\u8C03\u7528" aria-hidden="true">#</a></h2><p>Pocsuite3 api \u63D0\u4F9B\u4E86\u96C6\u6210\u8C03\u7528 <code>pocsuite3</code> \u7684\u5168\u90E8\u529F\u80FD\u51FD\u6570\uFF0C\u53EF\u53C2\u89C1\u6D4B\u8BD5\u7528\u4F8B <a href="https://github.com/knownsec/pocsuite3/blob/master/tests/test_import_pocsuite_execute.py" target="_blank" rel="noreferrer"><code>tests/test_import_pocsuite_execute.py</code></a>\u3002\u5178\u578B\u7684\u96C6\u6210\u8C03\u7528\u65B9\u6CD5\u5982\u4E0B\uFF1A</p><div class="language-python"><span class="copy"></span><pre><code><span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> init_pocsuite</span></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> start_pocsuite</span></span>
<span class="line"><span style="color:#89DDFF;font-style:italic;">from</span><span style="color:#A6ACCD;"> pocsuite3</span><span style="color:#89DDFF;">.</span><span style="color:#A6ACCD;">api </span><span style="color:#89DDFF;font-style:italic;">import</span><span style="color:#A6ACCD;"> get_results</span></span>
<span class="line"></span>
<span class="line"></span>
<span class="line"><span style="color:#C792EA;">def</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">run_pocsuite</span><span style="color:#89DDFF;">():</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#676E95;font-style:italic;"># config \u914D\u7F6E\u53EF\u53C2\u89C1\u547D\u4EE4\u884C\u53C2\u6570\uFF0C \u7528\u4E8E\u521D\u59CB\u5316 pocsuite3.lib.core.data.conf</span></span>
<span class="line"><span style="color:#A6ACCD;">    config </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">{</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">url</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">http://127.0.0.1:8080</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">http://127.0.0.1:21</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">],</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">poc</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">[</span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">ecshop_rce</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&#39;</span><span style="color:#C3E88D;">ftp_burst</span><span style="color:#89DDFF;">&#39;</span><span style="color:#89DDFF;">]</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#89DDFF;">}</span></span>
<span class="line"></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#82AAFF;">init_pocsuite</span><span style="color:#89DDFF;">(</span><span style="color:#82AAFF;">config</span><span style="color:#89DDFF;">)</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#82AAFF;">start_pocsuite</span><span style="color:#89DDFF;">()</span></span>
<span class="line"><span style="color:#A6ACCD;">    result </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">get_results</span><span style="color:#89DDFF;">()</span></span>
<span class="line"></span>
<span class="line"></span></code></pre></div><p><img src="`+n+'" alt=""></p>',14),r=[c];function i(D,y,F,A,C,d){return l(),o("div",null,r)}var f=p(t,[["render",i]]);export{h as __pageData,f as default};