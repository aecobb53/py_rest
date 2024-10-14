from .py_rest import PyRest


class TestService(PyRest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = None

    def _get_token(self):
        return 'Bearer TOKEN'

    def pre_try_mixin(self, request, *args, **kwargs):
        if self.token is None:
            self.token = self._get_token()
        if 'headers' not in request:
            request['headers'] = {'Authorization': self.token}

    def post_try_mixin(self, request, response, *args, **kwargs):
        if response.status_code == 401 or response.status_code == 403:
            self.token = None
