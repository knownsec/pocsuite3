# version 1.0
---------------
* Init publish

# version 1.2.1
---------------
* bugfix auto update error
* bugfix console mode load poc error
* update pocsuite3 banner

# version 1.2.2
---------------
* bugfix site-packages poc-console issue
* poc-console support to load absolute path
* poc-console will ignore case when use `search`

# version 1.2.5
---------------
* bugfix socks proxy

# version 1.2.6
---------------
* bugfix seebug poc

# version 1.2.7
---------------
* bugfix hook_requests 

# version 1.2.8
---------------
* support ceye token
* bugfix plugin from seebug
* refactoring ceye

# version 1.2.9
---------------
* seebug poc friendly load reminder
* new feature:displayed results after user interruption
* POC specifies third-party module verification failure
* customize option iter func
* Built-in http server

# version 1.2.10
---------------
* bugfix interpreter_option OptDict

# version 1.3.0
---------------
* new feature: `_verify` `_attack` function can directly return bool, str, dict, etc.
* new plugin: file report
* bugfix get_option() not support int

# version 1.3.1
---------------
* add confluence poc
* fix pocs/drupalgeddon2
* CYGWIN compatibility
* bugfix revision.py `stdout_encode`

# version 1.3.2
---------------
* bugfix poc thinkphp_rce

# version 1.3.3
---------------
fix #37 pocsuite3\lib\core\revision.py

# version 1.3.4
---------------
Cross-platform shell code generation

# version 1.3.5
---------------
* Add parameter `-c` for load configuration from the configuration file
* Add parameter `--comparsion` for comparing comparing both of zoomeye and shodan
* Interface supports from zoomeye,shodan and censys

# version 1.3.6
---------------
* Bugfix parameter `version`

# version 1.3.7
---------------
* add poc-plugin to load poc from `pocs` directories.

# version 1.3.8
---------------
* add field,option for compatibility with zipoc

# version 1.3.9
---------------
* 修复plugins选项加载绝对路径问题
* 修复加载pocs目录扫描部分报错问题
* PoC插件`add_poc`方法新增`fullname`参数用于定义加载poc名称
* 定义api模式方便shell集成

# version 1.4.0
---------------
* 在命令行下url和poc支持多个(空格分隔)
* 更换`optparse`到`argparse`

# version 1.4.1
---------------
* 修复由poc插件中由conf.poc引起的错误

# version 1.4.2
---------------
* 修复console模式下一处bug，https://github.com/knownsec/pocsuite3/pull/61

# version 1.4.3
---------------
* 加入PPT模式

# version 1.4.5
---------------
* update usage.md