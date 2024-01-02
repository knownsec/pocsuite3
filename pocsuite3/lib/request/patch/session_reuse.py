from pocsuite3.lib.core.data import kb


class ReuseSession:
    def __init__(self):
        self.session_queue = kb.session_queue
        self.session = None

    def __enter__(self):
        self.session = self.session_queue.get()
        return self.session

    def __exit__(self, *args):
        self.session_queue.put(self.session)


def api_request(method, url, **kwargs):
    with ReuseSession() as session:
        return session.request(method=method, url=url, **kwargs)
