import{_ as s,j as n,g as a,I as l}from"./chunks/framework.4d72ab90.js";const C=JSON.parse('{"title":"pocsuite.ini \u914D\u7F6E\u6587\u4EF6\u53C2\u6570\u8BF4\u660E","description":"","frontmatter":{},"headers":[],"relativePath":"guide/parameter-posuite-ini.md","lastUpdated":1657949701000}'),p={name:"guide/parameter-posuite-ini.md"},o=l(`<h1 id="pocsuite-ini-\u914D\u7F6E\u6587\u4EF6\u53C2\u6570\u8BF4\u660E" tabindex="-1">pocsuite.ini \u914D\u7F6E\u6587\u4EF6\u53C2\u6570\u8BF4\u660E <a class="header-anchor" href="#pocsuite-ini-\u914D\u7F6E\u6587\u4EF6\u53C2\u6570\u8BF4\u660E" aria-hidden="true">#</a></h1><p>\u914D\u7F6E\u6587\u4EF6\u793A\u4F8B\uFF1A</p><div class="language-ini"><span class="copy"></span><pre><code><span class="line"><span style="color:#89DDFF;">[Target]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; target url/cidr (e.g. &quot;http://www.site.com/vuln.php?id=1&quot;)</span></span>
<span class="line"><span style="color:#F07178;">url</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> https://www.google.com</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; scan multiple targets given in a textual file (one per line)</span></span>
<span class="line"><span style="color:#F07178;">url_file</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; add additional port to each target (e.g. 8080,8443)</span></span>
<span class="line"><span style="color:#F07178;">ports</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; load poc file from local or remote from seebug website</span></span>
<span class="line"><span style="color:#F07178;">poc</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; filter poc by keyword, e.g. cve-2021-22005</span></span>
<span class="line"><span style="color:#F07178;">poc_keyword</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> cve-2021-41773</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Mode]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; run poc with verify mode</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; run poc with attack mode</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; run poc with shell mode</span></span>
<span class="line"><span style="color:#F07178;">mode</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> verify</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Request]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; http cookie header value</span></span>
<span class="line"><span style="color:#F07178;">cookie</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; http host header value</span></span>
<span class="line"><span style="color:#F07178;">host</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; http referer header value</span></span>
<span class="line"><span style="color:#F07178;">referer</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; http user-agent header value (default random)</span></span>
<span class="line"><span style="color:#F07178;">agent</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; use a proxy to connect to the target url (protocol://host:port)</span></span>
<span class="line"><span style="color:#F07178;">proxy</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; proxy authentication credentials (name:password)</span></span>
<span class="line"><span style="color:#F07178;">proxy_cred</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; seconds to wait before timeout connection (default 10)</span></span>
<span class="line"><span style="color:#F07178;">timeout</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; time out retrials times (default 0)</span></span>
<span class="line"><span style="color:#F07178;">retry</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; delay between two request of one thread</span></span>
<span class="line"><span style="color:#F07178;">delay</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; extra headers (e.g. &quot;key1: value1\\nkey2: value2&quot;)</span></span>
<span class="line"><span style="color:#F07178;">headers</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Account]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; ceye token</span></span>
<span class="line"><span style="color:#F07178;">ceye_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; oob server</span></span>
<span class="line"><span style="color:#F07178;">oob_server</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; oob token</span></span>
<span class="line"><span style="color:#F07178;">oob_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; seebug token</span></span>
<span class="line"><span style="color:#F07178;">seebug_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; zoomeye token</span></span>
<span class="line"><span style="color:#F07178;">zoomeye_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; Shodan token</span></span>
<span class="line"><span style="color:#F07178;">shodan_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; fofa user</span></span>
<span class="line"><span style="color:#F07178;">fofa_user</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; fofa token</span></span>
<span class="line"><span style="color:#F07178;">fofa_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; quake token</span></span>
<span class="line"><span style="color:#F07178;">quake_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; hunter token</span></span>
<span class="line"><span style="color:#F07178;">hunter_token</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; Censys uid</span></span>
<span class="line"><span style="color:#F07178;">censys_uid</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; Censys secret</span></span>
<span class="line"><span style="color:#F07178;">censys_secret</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Modules]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; zoomeye dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; zoomeye dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_zoomeye</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; shodan dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_shodan</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; censys dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_censys</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; fofa dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_fofa</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; quake dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_quake</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; hunter dork used for search</span></span>
<span class="line"><span style="color:#F07178;">dork_hunter</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; max page used in search api</span></span>
<span class="line"><span style="color:#F07178;">max_page</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> 1</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; search type used in zoomeye api, web or host</span></span>
<span class="line"><span style="color:#F07178;">search_type</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> host</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; seebug keyword used for search</span></span>
<span class="line"><span style="color:#F07178;">vul_keyword</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; seebug ssvid number for target poc</span></span>
<span class="line"><span style="color:#F07178;">ssvid</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; connect back host for target poc in shell mode</span></span>
<span class="line"><span style="color:#F07178;">connect_back_host</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; connect back port for target poc in shell mode</span></span>
<span class="line"><span style="color:#F07178;">connect_back_port</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; enable TLS listener in shell mode</span></span>
<span class="line"><span style="color:#F07178;">enable_tls_listener</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; compare popular web search engines</span></span>
<span class="line"><span style="color:#F07178;">comparison</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; whether dork is in base64 format</span></span>
<span class="line"><span style="color:#F07178;">dork_b64</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Optimization]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; output file to write (json lines format)</span></span>
<span class="line"><span style="color:#F07178;">output_path</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; load plugins to execute</span></span>
<span class="line"><span style="color:#F07178;">plugins</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; user defined poc scripts path</span></span>
<span class="line"><span style="color:#F07178;">pocs_path</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; max number of concurrent network requests (default 150)</span></span>
<span class="line"><span style="color:#F07178;">threads</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; automatically choose defaut choice without asking</span></span>
<span class="line"><span style="color:#F07178;">batch</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; check install_requires</span></span>
<span class="line"><span style="color:#F07178;">check_requires</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; activate quiet mode, working without logger</span></span>
<span class="line"><span style="color:#F07178;">quiet</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; hiden sensitive information when published to the network</span></span>
<span class="line"><span style="color:#F07178;">ppt</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; use scapy capture flow</span></span>
<span class="line"><span style="color:#F07178;">pcap</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; export suricata rules, default export request and response</span></span>
<span class="line"><span style="color:#F07178;">rule</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; only export suricata request rule</span></span>
<span class="line"><span style="color:#F07178;">rule_req</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> False</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; specify the name of the export rule file</span></span>
<span class="line"><span style="color:#F07178;">rule_filename</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"></span>
<span class="line"><span style="color:#89DDFF;">[Poc options]</span></span>
<span class="line"><span style="color:#676E95;font-style:italic;">; show all definition options</span></span>
<span class="line"><span style="color:#F07178;">show_options</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">=</span></span>
<span class="line"></span></code></pre></div>`,3),e=[o];function t(c,r,i,y,D,F){return a(),n("div",null,e)}var f=s(p,[["render",t]]);export{C as __pageData,f as default};
