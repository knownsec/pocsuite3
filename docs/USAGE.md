# Usage

- **pocsuite**: a cool and hackable commane line program

## pocsuite

Enter into `pocsuite` directory, execute `python cli.py`. It supports double mode:

 - ```verify```
 - ```attack```
 - ```shell```

You can also use ```python cli.py -h``` for more details.

```
Usage: pocsuite [options]

Options:
  -h, --help            show this help message and exit
  --version             Show program's version number and exit
  --update              Update Pocsuite
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -f URL_FILE, --file=URL_FILE
                        Scan multiple targets given in a textual file
    -r POC              Load POC file from local or remote from seebug website

  Mode:
    Pocsuite running mode options

    --verify            Run poc with verify mode
    --attack            Run poc with attack mode
    --shell             Run poc with shell mode

  Request:
    Network request options

    --cookie=COOKIE     HTTP Cookie header value
    --host=HOST         HTTP Host header value
    --referer=REFERER   HTTP Referer header value
    --user-agent=AGENT  HTTP User-Agent header value
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --proxy-cred=PROXY_CRED
                        Proxy authentication credentials (name:password)
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
    --retry=RETRY       Time out retrials times.
    --delay=DELAY       Delay between two request of one thread
    --headers=HEADERS   Extra headers (e.g. "key1: value1\nkey2: value2")

  Account:
    Telnet404 account options

    --login-user=LOGIN_USER
                        Telnet404 login user
    --login-pass=LOGIN_PASS
                        Telnet404 login password

  Modules:
    Modules(Seebug Zoomeye CEye Listener) options

    --dork=DORK         Zoomeye dork used for search.
    --max-page=MAX_PAGE
                        Max page used in ZoomEye API(10 targets/Page).
    --search-type=SEARCH_TYPE
                        search type used in ZoomEye API, web or host
    --vul-keyword=VUL_KEYWORD
                        Seebug keyword used for search.
    --ssv-id=SSVID      Seebug SSVID number for target PoC.
    --rhost=CONNECT_BACK_HOST
                        Connect back host for target PoC in shell mode
    --rport=CONNECT_BACK_PORT
                        Connect back port for target PoC in shell mode

  Optimization:
    Optimization options

    --plugins=PLUGINS   Load plugins to execute
    --pocs-path=POCS_PATH
                        User defined poc scripts path
    --threads=THREADS   Max number of concurrent network requests (default 1)
    --batch=BATCH       Automatically choose defaut choice without asking.
    --requires          Check install_requires
    --quiet             Activate quiet mode, working without logger.

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

If you have good ideas, please show them on your way.
