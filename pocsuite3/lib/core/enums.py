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
    HTTP_Parameter_Pollution = 'HTTP Parameter Pollution'  # HTTP 参数污染
    Backdoor = 'Backdoor'  # 后门
    Insecure_Cookie_Handling = 'Insecure Cookie Handling'  # Cookie 验证错误
    CSRF = 'CSRF'  # 跨站请求伪造
    ShellCode = 'ShellCode'  # ShellCode
    SQL_injection = 'SQL injection'  # SQL 注入
    Arbitrary_File_Download = 'Arbitrary File Download'  # 任意文件下载
    Arbitrary_File_Creation = 'Arbitrary File Creation'  # 任意文件创建
    Arbitrary_File_Deletion = 'Arbitrary File Deletion'  # 任意文件删除
    Arbitrary_File_Read = 'Arbitrary File Read'  # 任意文件读取
    Other = 'Other'  # 其他类型
    Variable_Coverage = 'Variable Coverage'  # 变量覆盖
    Command_Execution = 'Command Execution'  # 命令执行
    Injecting_Malware_Codes = 'Injecting Malware Codes'  # 嵌入恶意代码
    Weak_Password = 'Weak Password'  # 弱密码
    Denial_Of_service = 'Denial Of service'  # 拒绝服务
    Database_Found = 'Database Found'  # 数据库发现
    Upload_Files = 'Upload Files'  # 文件上传
    Remote_File_Inclusion = 'Remote File Inclusion'  # 远程文件包含
    Local_Overflow = 'Local Overflow'  # 本地溢出
    Privilege_Escalation = 'Privilege Escalation'  # 权限提升
    Information_Disclosure = 'Information Disclosure'  # 信息泄漏
    Login_Bypass = 'Login Bypass'  # 登录绕过
    Path_Traversal = 'Path Traversal'  # 目录穿越
    Resolve_Error = 'Resolve Error'  # 解析错误
    Unauthorized_Access = 'Unauthorized Access'  # 越权访问
    XSS = 'XSS'  # 跨站脚本
    Path_Disclosure = 'Path Disclosure'  # 路径泄漏
    Code_Execution = 'Code Execution'  # 代码执行
    Remote_Password_Change = 'Remote Password Change'  # 远程密码修改
    Remote_Overflow = 'Remote Overflow'  # 远程溢出
    Directory_Listing = 'Directory Listing'  # 目录遍历
    Null_Byte_Injection = 'Null Byte Injection'  # 空字节注入
    Man_in_the_middle = 'Man-in-the-middle'  # 中间人攻击
    Format_String = 'Format String'  # 格式化字符串
    Buffer_Overflow = 'Buffer Overflow'  # 缓冲区溢出
    HTTP_Request_Splitting = 'HTTP Request Splitting'  # HTTP 请求拆分
    CRLF_Injection = 'CRLF Injection'  # CRLF 注入
    XML_Injection = 'XML Injection'  # XML 注入
    Local_File_Inclusion = 'Local File Inclusion'  # 本地文件包含
    Credential_Prediction = 'Credential Prediction'  # 证书预测
    HTTP_Response_Splitting = 'HTTP Response Splitting'  # HTTP 响应拆分
    SSI_Injection = 'SSI Injection'  # SSI 注入
    Out_of_Memory = 'Out of Memory'  # 内存溢出
    Integer_Overflows = 'Integer Overflows'  # 整数溢出
    HTTP_Response_Smuggling = 'HTTP Response Smuggling'  # HTTP 响应伪造
    HTTP_Request_Smuggling = 'HTTP Request Smuggling'  # HTTP 请求伪造
    Content_Spoofing = 'Content Spoofing'  # 内容欺骗
    XQuery_Injection = 'XQuery Injection'  # XQuery 注入
    Buffer_Over_read = 'Buffer Over-read'  # 缓存区过读
    Brute_Force = 'Brute Force'  # 暴力破解
    LDAP_Injection = 'LDAP Injection'  # LDAP 注入
    Security_Mode_Bypass = 'Security Mode Bypass'  # 安全模式绕过
    Backup_File_Found = 'Backup File Found'  # 备份文件发现
    XPath_Injection = 'XPath Injection'  # XPath 注入
    URL_Redirector_Abuse = 'URL Redirector Abuse'  # URL 重定向
    Code_Disclosure = 'Code Disclosure'  # 代码泄漏
    Use_After_Free = 'Use After Free'  # 释放后重用
    DNS_Hijacking = 'DNS Hijacking'  # DNS 劫持
    Improper_Input_Validation = 'Improper Input Validation'  # 错误的输入验证
    UXSS = 'UXSS'  # 通用跨站脚本
