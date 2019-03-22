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
    LINUX = "Linux"
    WINDOWS = "Windows"


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
    PROTOCOL.TALENT = "Telent"
    PROTOCOL.REDIS = "Redis"
