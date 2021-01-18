from pocsuite3.lib.core.datatype import AttribDict


class LOGGING_LEVELS:
    NOTSET = 0
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class CUSTOM_LOGGING:
    SYSINFO = 21
    SUCCESS = 22
    ERROR = 23
    WARNING = 24


class OUTPUT_STATUS:
    SUCCESS = 1
    FAILED = 0


class HTTP_HEADER:
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"


class PROXY_TYPE:
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"
    SOCKS5H = "SOCKS5H"


class ERROR_TYPE_ID:
    NOTIMPLEMENTEDERROR = 2
    CONNECTIONERROR = 3.0
    HTTPERROR = 3.1
    CONNECTTIMEOUT = 3.2
    TOOMANYREDIRECTS = 3.3
    OTHER = 4


class OS:
    LINUX = "linux"
    WINDOWS = "windows"


class OS_ARCH:
    X86 = "32bit"
    X64 = "64bit"


class ENCODER_TPYE:
    XOR = "xor"
    ALPHANUMERIC = "alphanum"
    ROT_13 = "rot_13"
    FNSTENV_XOR = "fnstenv"
    JUMPCALL_XOR = "jumpcall"


class SHELLCODE_TYPE:
    JSP = "jsp"
    JAR = "jar"
    WAR = "war"
    PYTHON = "python"
    PHP = "php"
    ASPX = "aspx"


class SHELLCODE_CONNECTION:
    BIND = 'bind'
    REVERSE = 'reverse'


class PLUGIN_TYPE:
    TARGETS = 'targets'
    POCS = 'pocs'
    RESULTS = 'results'


class AUTOCOMPLETE_TYPE:
    SQL = 0
    OS = 1
    POCSUITE = 2
    API = 3
    CONSOLE = 4


class POC_CATEGORY:
    EXPLOITS = AttribDict()
    EXPLOITS.WEBAPP = 'WebApp'
    EXPLOITS.DOS = 'DoS'
    EXPLOITS.REMOTE = 'Remote'
    EXPLOITS.LOCAL = 'Local'

    TOOLS = AttribDict()
    TOOLS.CRACK = 'Crack'

    PROTOCOL = AttribDict()
    PROTOCOL.HTTP = "Http"
    PROTOCOL.FTP = "Ftp"
    PROTOCOL.SSH = "Ssh"
    PROTOCOL.TELENT = "Telent"
    PROTOCOL.REDIS = "Redis"


class OPTION_TYPE:
    BOOLEAN = "boolean"
    INTEGER = "integer"
    FLOAT = "float"
    STRING = "string"


class VUL_TYPE:
    HTTP_PARAMETER_POLLUTION = 'HTTP Parameter Pollution'       # HTTP 参数污染
    BACKDOOR = 'Backdoor'                                       # 后门
    INSECURE_COOKIE_HANDLING = 'Insecure Cookie Handling'       # Cookie 验证错误
    CSRF = 'CSRF'                                               # 跨站请求伪造
    SHELLCODE = 'ShellCode'                                     # ShellCode
    SQL_INJECTION = 'SQL Injection'                             # SQL 注入
    ARBITRARY_FILE_DOWNLOAD = 'Arbitrary File Download'         # 任意文件下载
    ARBITRARY_FILE_CREATION = 'Arbitrary File Creation'         # 任意文件创建
    ARBITRARY_FILE_DELETION = 'Arbitrary File Deletion'         # 任意文件删除
    ARBITRARY_FILE_READ = 'Arbitrary File Read'                 # 任意文件读取
    OTHER = 'Other'                                             # 其他类型
    VARIABLE_COVERAGE = 'Variable Coverage'                     # 变量覆盖
    COMMAND_EXECUTION = 'Command Execution'                     # 命令执行
    INJECTING_MALWARE_CODES = 'Injecting Malware Codes'         # 嵌入恶意代码
    WEAK_PASSWORD = 'Weak Password'                             # 弱密码
    DENIAL_OF_SERVICE = 'Denial Of service'                     # 拒绝服务
    DATABASE_FOUND = 'Database Found'                           # 数据库发现
    UPLOAD_FILES = 'Upload Files'                               # 文件上传
    REMOTE_FILE_INCLUSION = 'Remote File Inclusion'             # 远程文件包含
    LOCAL_OVERFLOW = 'Local Overflow'                           # 本地溢出
    PRIVILEGE_ESCALATION = 'Privilege Escalation'               # 权限提升
    INFORMATION_DISCLOSURE = 'Information Disclosure'           # 信息泄漏
    LOGIN_BYPASS = 'Login Bypass'                               # 登录绕过
    PATH_TRAVERSAL = 'Path Traversal'                           # 目录穿越
    RESOLVE_ERROR = 'Resolve Error'                             # 解析错误
    UNAUTHORIZED_ACCESS = 'Unauthorized Access'                 # 越权访问
    XSS = 'XSS'                                                 # 跨站脚本
    PATH_DISCLOSURE = 'Path Disclosure'                         # 路径泄漏
    CODE_EXECUTION = 'Code Execution'                           # 代码执行
    REMOTE_PASSWORD_CHANGE = 'Remote Password Change'           # 远程密码修改
    REMOTE_OVERFLOW = 'Remote Overflow'                         # 远程溢出
    DIRECTORY_LISTING = 'Directory Listing'                     # 目录遍历
    NULL_BYTE_INJECTION = 'Null Byte Injection'                 # 空字节注入
    MAN_IN_THE_MIDDLE = 'Man-in-the-middle'                     # 中间人攻击
    FORMAT_STRING = 'Format String'                             # 格式化字符串
    BUFFER_OVERFLOW = 'Buffer Overflow'                         # 缓冲区溢出
    HTTP_REQUEST_SPLITTING = 'HTTP Request Splitting'           # HTTP 请求拆分
    CRLF_INJECTION = 'CRLF Injection'                           # CRLF 注入
    XML_INJECTION = 'XML Injection'                             # XML 注入
    LOCAL_FILE_INCLUSION = 'Local File Inclusion'               # 本地文件包含
    CREDENTIAL_PREDICTION = 'Credential Prediction'             # 证书预测
    HTTP_RESPONSE_SPLITTING = 'HTTP Response Splitting'         # HTTP 响应拆分
    SSI_INJECTION = 'SSI Injection'                             # SSI 注入
    OUT_OF_MEMORY = 'Out of Memory'                             # 内存溢出
    INTEGER_OVERFLOWS = 'Integer Overflows'                     # 整数溢出
    HTTP_RESPONSE_SMUGGLING = 'HTTP Response Smuggling'         # HTTP 响应伪造
    HTTP_REQUEST_SMUGGLING = 'HTTP Request Smuggling'           # HTTP 请求伪造
    CONTENT_SPOOFING = 'Content Spoofing'                       # 内容欺骗
    XQUERY_INJECTION = 'XQuery Injection'                       # XQuery 注入
    BUFFER_OVER_READ = 'Buffer Over-read'                       # 缓存区过读
    BRUTE_FORCE = 'Brute Force'                                 # 暴力破解
    LDAP_INJECTION = 'LDAP Injection'                           # LDAP 注入
    SECURITY_MODE_BYPASS = 'Security Mode Bypass'               # 安全模式绕过
    BACKUP_FILE_FOUND = 'Backup File Found'                     # 备份文件发现
    XPATH_INJECTION = 'XPath Injection'                         # XPath 注入
    URL_REDIRECTOR_ABUSE = 'URL Redirector Abuse'               # URL 重定向
    CODE_DISCLOSURE = 'Code Disclosure'                         # 代码泄漏
    USE_AFTER_FREE = 'Use After Free'                           # 释放后重用
    DNS_HIJACKING = 'DNS Hijacking'                             # DNS 劫持
    IMPROPER_INPUT_VALIDATION = 'Improper Input Validation'     # 错误的输入验证
    UXSS = 'UXSS'                                               # 通用跨站脚本
