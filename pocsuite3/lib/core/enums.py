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
    BACKDOOR = 'Backdoor'
    INSECURE_COOKIE_HANDLING = 'Insecure Cookie Handling'
    CSRF = 'CSRF'
    XSS = 'XSS'
    UXSS = 'UXSS'
    SSRF = 'Server-Side Request Forgery'
    SHELLCODE = 'ShellCode'
    SQL_INJECTION = 'SQL Injection'
    ARBITRARY_FILE_DOWNLOAD = 'Arbitrary File Download'
    ARBITRARY_FILE_CREATION = 'Arbitrary File Creation'
    ARBITRARY_FILE_DELETION = 'Arbitrary File Deletion'
    ARBITRARY_FILE_READ = 'Arbitrary File Read'
    OTHER = 'Other'
    VARIABLE_COVERAGE = 'Variable Coverage'
    COMMAND_EXECUTION = 'Command Execution'
    INJECTING_MALWARE_CODES = 'Injecting Malware Codes'
    WEAK_PASSWORD = 'Weak Password'
    DENIAL_OF_SERVICE = 'Denial Of service'
    DATABASE_FOUND = 'Database Found'
    UPLOAD_FILES = 'Upload Files'
    LOCAL_OVERFLOW = 'Local Overflow'
    PRIVILEGE_ESCALATION = 'Privilege Escalation'
    INFORMATION_DISCLOSURE = 'Information Disclosure'
    LOGIN_BYPASS = 'Login Bypass'
    PATH_TRAVERSAL = 'Path Traversal'
    RESOLVE_ERROR = 'Resolve Error'
    UNAUTHORIZED_ACCESS = 'Unauthorized Access'
    PATH_DISCLOSURE = 'Path Disclosure'
    CODE_EXECUTION = 'Code Execution'
    REMOTE_PASSWORD_CHANGE = 'Remote Password Change'
    REMOTE_OVERFLOW = 'Remote Overflow'
    DIRECTORY_LISTING = 'Directory Listing'
    NULL_BYTE_INJECTION = 'Null Byte Injection'
    MAN_IN_THE_MIDDLE = 'Man-in-the-middle'
    FORMAT_STRING = 'Format String'
    BUFFER_OVERFLOW = 'Buffer Overflow'
    CRLF_INJECTION = 'CRLF Injection'
    XML_INJECTION = 'XML Injection'
    LOCAL_FILE_INCLUSION = 'Local File Inclusion'
    REMOTE_FILE_INCLUSION = 'Remote File Inclusion'
    CREDENTIAL_PREDICTION = 'Credential Prediction'
    HTTP_PARAMETER_POLLUTION = 'HTTP Parameter Pollution'
    HTTP_REQUEST_SPLITTING = 'HTTP Request Splitting'
    HTTP_RESPONSE_SPLITTING = 'HTTP Response Splitting'
    HTTP_RESPONSE_SMUGGLING = 'HTTP Response Smuggling'
    HTTP_REQUEST_SMUGGLING = 'HTTP Request Smuggling'
    SSI_INJECTION = 'SSI Injection'
    OUT_OF_MEMORY = 'Out of Memory'
    INTEGER_OVERFLOWS = 'Integer Overflows'
    CONTENT_SPOOFING = 'Content Spoofing'
    XQUERY_INJECTION = 'XQuery Injection'
    BUFFER_OVER_READ = 'Buffer Over-read'
    BRUTE_FORCE = 'Brute Force'
    LDAP_INJECTION = 'LDAP Injection'
    SECURITY_MODE_BYPASS = 'Security Mode Bypass'
    BACKUP_FILE_FOUND = 'Backup File Found'
    XPATH_INJECTION = 'XPath Injection'
    URL_REDIRECTOR_ABUSE = 'URL Redirector Abuse'
    CODE_DISCLOSURE = 'Code Disclosure'
    USE_AFTER_FREE = 'Use After Free'
    DNS_HIJACKING = 'DNS Hijacking'
    IMPROPER_INPUT_VALIDATION = 'Improper Input Validation'
    UAF = 'Use After Free'
