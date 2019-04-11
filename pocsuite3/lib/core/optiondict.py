# Family: {"parameter name": "parameter datatype"},
# --OR--
# Family: {"parameter name": ("parameter datatype", "category name used for common outputs feature")},

optDict = {
    'Target': {
        'url': 'string',
        'url_file': 'string',
        'poc': 'string',
        'configFile': 'string'
    },
    'Mode': {
        'mode': 'string'
    },
    'Request': {
        'cookie': 'string',
        'host': 'string',
        'referer': 'string',
        'agent': 'string',
        'random_agent': 'boolean',
        'proxy': 'string',
        'proxy_cred': 'string',
        'timeout': 'string',
        'retry': 'float',
        'delay': 'string',
        'headers': 'string'
    },
    'Account': {
        'login_user': 'string',
        'login_pass': 'string'
    },
    'Modules': {
        'dork': 'string',
        'max_page': 'integer',
        'search_type': 'string',
        'vul_keyword': 'string',
        'ssvid': 'string',
        'connect_back_host': 'string',
        'connect_back_port': 'string',
        "comparison": "boolean"
    },
    'Optimization': {
        'plugins': 'string',
        'pocs_path': 'string',
        'threads': 'integer',
        'batch': 'string',
        'check_requires': 'boolean',
        'quiet': 'boolean'
    }
}
