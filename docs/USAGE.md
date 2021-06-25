# Usage

- **pocsuite**: a cool and hackable commane line program

## pocsuite

Enter into `pocsuite` directory, execute `python cli.py`. It supports double mode:

 - ```verify```
 - ```attack```
 - ```shell```

You can also use ```python cli.py -h``` for more details.

```
usage: pocsuite [options]

optional arguments:
  -h, --help            show this help message and exit
  --version             Show program's version number and exit
  --update              Update Pocsuite
  -v {0,1,2,3,4,5,6}    Verbosity level: 0-6 (default 1)

Target:
  At least one of these options has to be provided to define the target(s)

  -u URL [URL ...], --url URL [URL ...]
                        Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  -f URL_FILE, --file URL_FILE
                        Scan multiple targets given in a textual file
  -r POC [POC ...]      Load POC file from local or remote from seebug website
  -c CONFIGFILE         Load options from a configuration INI file

Mode:
  Pocsuite running mode options

  --verify              Run poc with verify mode
  --attack              Run poc with attack mode
  --shell               Run poc with shell mode

Request:
  Network request options

  --cookie COOKIE       HTTP Cookie header value
  --host HOST           HTTP Host header value
  --referer REFERER     HTTP Referer header value
  --user-agent AGENT    HTTP User-Agent header value
  --random-agent        Use randomly selected HTTP User-Agent header value
  --proxy PROXY         Use a proxy to connect to the target URL
  --proxy-cred PROXY_CRED
                        Proxy authentication credentials (name:password)
  --timeout TIMEOUT     Seconds to wait before timeout connection (default 30)
  --retry RETRY         Time out retrials times.
  --delay DELAY         Delay between two request of one thread
  --headers HEADERS     Extra headers (e.g. "key1: value1\nkey2: value2")

Account:
  Telnet404、Shodan、CEye、Fofa account options

  --login-user LOGIN_USER
                        Telnet404 login user
  --login-pass LOGIN_PASS
                        Telnet404 login password
  --shodan-token SHODAN_TOKEN
                        Shodan token
  --fofa-user FOFA_USER
                        fofa user
  --fofa-token FOFA_TOKEN
                        fofa token
  --censys-uid CENSYS_UID
                        Censys uid
  --censys-secret CENSYS_SECRET
                        Censys secret

Modules:
  Modules(Seebug、Zoomeye、CEye、Fofa Listener) options

  --dork DORK           Zoomeye dork used for search.
  --dork-b64            Whether dork is in base64 format
  --dork-zoomeye DORK_ZOOMEYE
                        Zoomeye dork used for search.
  --dork-shodan DORK_SHODAN
                        Shodan dork used for search.
  --dork-censys DORK_CENSYS
                        Censys dork used for search.
  --dork-fofa DORK_FOFA
                        Fofa dork used for search.
  --max-page MAX_PAGE   Max page used in ZoomEye API(10 targets/Page).
  --search-type SEARCH_TYPE
                        search type used in ZoomEye API, web or host
  --vul-keyword VUL_KEYWORD
                        Seebug keyword used for search.
  --ssv-id SSVID        Seebug SSVID number for target PoC.
  --lhost CONNECT_BACK_HOST
                        Connect back host for target PoC in shell mode
  --lport CONNECT_BACK_PORT
                        Connect back port for target PoC in shell mode
  --comparison          Compare popular web search engines
  --pcap                capture package in verify mode 

Optimization:
  Optimization options

  --plugins PLUGINS     Load plugins to execute
  --pocs-path POCS_PATH
                        User defined poc scripts path
  --threads THREADS     Max number of concurrent network requests (default 1)
  --batch BATCH         Automatically choose defaut choice without asking.
  --requires            Check install_requires
  --quiet               Activate quiet mode, working without logger.
  --rule                Export rules, default export reqeust and response.
  --rule-req            Only export request rule.
  --rule-filename       Specify the name of the export rule file.
  --ppt                 Hiden sensitive information when published to the
                        network

Poc options:
  definition options for PoC
```

**-f, --file URLFILE**

Scan multiple targets given in a textual file

```
$ python cli.py -r tests/poc_example.py -f url.txt --verify
```

> Attack batch processing mode only need to replace the ```--verify``` as ``` --attack```.

**-r POCFILE**

POCFILE can be a file or Seebug SSVID. pocsuite plugin can load poc codes from any where.


```
$ python cli.py -r ssvid-97343 -u http://www.example.com --shell
```

**--verify**

Run poc with verify mode. PoC(s) will be only used for a vulnerability scanning.

```
$ python cli.py -r pocs/poc_example.py -u http://www.example.com/ --verify
```

**--attack**

Run poc with attack mode, PoC(s) will be exploitable, and it may allow hackers/researchers break into labs.

```
$ python cli.py -r pocs/poc_example.py -u http://www.example.com/ --attack
```

**--shell**

Run poc with shell mode, PoC will be exploitable, when PoC shellcode successfully executed, pocsuite3 will drop into interactive shell.

```
$ python cli.py -r pocs/poc_example.py -u http://www.example.com/ --shell
```

**--threads THREADS**

Using multiple threads, the default number of threads is 1

```
$ python cli.py -r tests/ -f url.txt --verify --threads 10
```

**--dork DORK**

If you are a [**ZoomEye**](https://www.zoomeye.org/) user, The API is a cool and hackable interface. ex:

Search redis server with ```port:6379``` and ```redis``` keyword.


```
$ python cli.py --dork 'port:6379' --vul-keyword 'redis' --max-page 2

```
**--dork-shodan DORK**

 If you are a [**Shodan**](https://www.shodan.io/) user, The API is a cool and hackable interface. ex:

 Search libssh server  with  `libssh` keyword.

 ```
 python3 cli.py -r pocs/libssh_auth_bypass.py --dork-shodan libssh --thread 10
 ```

**--dork-fofa DORK**

 If you are a [**Fofa**](fofa) user, The API is a cool and hackable interface. ex:

 Search web server thinkphp with  `body="thinkphp"` keyword.


 ```
 $ python3 cli.py -r pocs/check_http_status.py --dork-fofa 'body="thinkphp"' --search-type web  --thread 10
 ```

**--dork-quake DORK**

 If you are a [**Quake**](quake) user, The API is a cool and hackable interface. ex:

 Search web server thinkphp with  `app:"ThinkPHP"` keyword.


 ```
 $ python3 cli.py -r pocs/check_http_status.py --dork-quake 'app:"ThinkPHP"' --thread 10
 ```

**--dork-b64**

 In order to solve the problem of escaping, use --dork-b64 to tell the program that you are passing in base64 encoded dork.
 

```
$ python cli.py --dork cG9ydDo2Mzc5 --vul-keyword 'redis' --max-page 2 --dork-b64
```

**--rule**
 Export suricate rules, default export reqeust and response and The poc directory is /pocs/.
 
 Use the --pocs-path parameter to set the directory where the poc needs to be ruled
 
```
$ python cli.py --rule
```

**--rule-req**
 In some cases, we may only need the request rule, --rule-req only export request rule.

```
$ python cli.py --rule-req
```

If you have good ideas, please show them on your way.

## 常用命令
	- pocsuite -u http://example.com -r example.py -v 2 # 基础用法 v2开启详细信息

	- pocsuite -u http://example.com -r example.py -v 2 --shell # shell反连模式，基础用法 v2开启详细信息

	- pocsuite -r redis.py --dork service:redis --threads 20 # 从zoomeye搜索redis目标批量检测，线程设置为20

	- pocsuite -u http://example.com --plugins poc_from_pocs,html_report # 加载poc目录下所有poc,并将结果保存为html

	- pocsuite -f batch.txt --plugins poc_from_pocs,html_report # 从文件中加载目标，并使用poc目录下poc批量扫描

	- pocsuite -u 10.0.0.0/24 -r example.py --plugins target_from_cidr # 加载CIDR目标

	- pocsuite -u http://example.com -r ecshop_rce.py --attack --command "whoami" # ecshop poc中实现了自定义命令`command`,可以从外部参数传递。
