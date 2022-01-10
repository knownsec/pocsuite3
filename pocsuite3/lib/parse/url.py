from pocsuite3.lib.utils import urlparse


class URL:

    def __init__(self, schema: bytes, host: bytes, port, path: bytes,
                 query: bytes, fragment: bytes, userinfo: bytes):
        self.schema = schema.decode('utf-8')
        self.host = host.decode('utf-8')
        if port and port != 0:
            self.port = port
        else:
            if schema == b'https':
                self.port = 443
            else:
                self.port = 80
        self.path = path.decode('utf-8') if path else ''
        self.query = query.decode('utf-8') if query else None
        self.fragment = fragment.decode('utf-8') if fragment else None
        self.userinfo = userinfo.decode('utf-8') if userinfo else None
        self.netloc = self.schema + '://' + self.host + ':' + str(self.port)

    @property
    def raw(self):
        return self.netloc + (self.path or '') + (self.query or '') + (self.fragment or '')

    def __repr__(self):
        return ('<URL schema: {!r}, host: {!r}, port: {!r}, path: {!r}, '
                'query: {!r}, fragment: {!r}, userinfo: {!r}>'
                .format(self.schema, self.host, self.port, self.path, self.query, self.fragment, self.userinfo))


def parse_url(url):
    try:
        parsed = urlparse(url)
        userinfo = b'{parsed.username}:{parsed.password}'
        return URL(parsed.scheme, parsed.hostname, parsed.port, parsed.path, parsed.query, parsed.fragment, userinfo)
    except Exception:
        raise("invalid url {!r}".format(url))
