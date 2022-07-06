# Family: {"parameter name": "parameter datatype"},
# --OR--
# Family: {"parameter name": ("parameter datatype", "category name used for common outputs feature")},

optDict = {
    'Target': {
        'url': 'string',
        'url_file': 'string',
        'ports': 'string',
        'poc': 'string',
        'poc_keyword': 'string',
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
        'proxy': 'string',
        'proxy_cred': 'string',
        'timeout': 'float',
        'retry': 'integer',
        'delay': 'string',
        'headers': 'string'
    },
    'Account': {
        'ceye_token': 'string',
        'oob_server': 'string',
        'oob_token': 'string',
        'seebug_token': 'string',
        'zoomeye_token': 'string',
        'shodan_token': 'string',
        'fofa_user': 'string',
        'fofa_token': 'string',
        'quake_token': 'string',
        'hunter_token': 'string',
        'censys_uid': 'string',
        'censys_secret': 'string'
    },
    'Modules': {
        'dork': 'string',
        'dork_zoomeye': 'string',
        'dork_shodan': 'string',
        'dork_fofa': 'string',
        'dork_quake': 'string',
        'dork_hunter': 'string',
        'dork_censys': 'string',
        'max_page': 'integer',
        'search_type': 'string',
        'vul_keyword': 'string',
        'ssvid': 'string',
        'connect_back_host': 'string',
        'connect_back_port': 'string',
        'enable_tls_listener': 'boolean',
        "comparison": 'boolean',
        'dork_b64': 'boolean'
    },
    'Optimization': {
        'output_path': 'string',
        'plugins': 'string',
        'pocs_path': 'string',
        'threads': 'integer',
        'batch': 'string',
        'check_requires': 'boolean',
        'quiet': 'boolean',
        'ppt': 'boolean',
        'pcap': 'boolean',
        'rule': 'boolean',
        'rule_req': 'boolean',
        'rule_filename': 'string'
    },
    'Poc options': {
        'show_options': 'boolean'
    }
}
