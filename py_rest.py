import requests

from typing import Dict, List
from time import sleep


class PyRest:
    def __init__(self,
        base_url: str | None = None,
        base_headers: Dict | None = None,
        base_timeout: int | None = None,
        retries: int = 0,
        retry_pause_seconds: int = 0,
        backoff_seconds: int = 0,
        verbose: bool = False,
        logger=None,
        save_request_directory: str | None = None,
        redacted_keys: List[str] = ['Authorization']):

        self.base_url = base_url
        self.base_headers = base_headers
        self.base_timeout = base_timeout
        self.rest_tries = retries + 1
        self.retry_pause_seconds = retry_pause_seconds
        self.backoff_seconds = backoff_seconds
        self.verbose = verbose
        self.logger = logger
        self.save_request_directory = save_request_directory
        self.redacted_keys = redacted_keys

    def make_call(self,
        method: str,
        url: str | None = None,
        base_url: str | None = None,
        endpoint: str | None = None,
        params: Dict | None = None,
        data: Dict | None = None,
        json: Dict | None = None,
        body: Dict | None = None,
        headers: Dict | None = None,
        cookies: Dict | None = None,
        filepaths: Dict | str | None = None,
        # auth
        timeout: int | None = None,
        # allow_redirects
        # proxies
        # verify
        # stream
        # cert
        rest_tries: int | None = None,
        retry_pause_seconds: int | None = None,
        backoff_seconds: int | None = None,
        verbose: bool | None = None,
        logger=None,
        allow_errors: bool = True):
        if rest_tries is None:
            rest_tries = self.rest_tries
        if retry_pause_seconds is None:
            retry_pause_seconds = self.retry_pause_seconds
        if backoff_seconds is None:
            backoff_seconds = self.backoff_seconds
        if verbose is None:
            verbose = self.verbose
        if logger is None:
            logger = self.logger

        # Set up conditional parts of the request
        if url:
            if base_url or endpoint:
                raise ValueError(f"If url is provided, you cant use base_url/endpoint")
        else:
            base_url = base_url or self.base_url
            if not base_url:
                raise ValueError(f"If url is not provided, base_url must be")
            if endpoint:
                if not base_url.endswith('/') or not endpoint.startswith('/'):
                    endpoint = '/' + endpoint
                base_url += endpoint
            url = base_url
        if isinstance(filepaths, str):
            filepaths = {'file': filepaths}

        # Set up the call
        call = {'url': url}
        if params:
            if 'params' not in call:
                call['params'] = {}
            call['params'].update(params)
        if data:
            if 'data' not in call:
                call['data'] = {}
            call['data'].update(data)
        if json:
            if 'json' not in call:
                call['json'] = {}
            call['json'].update(json)
        if body:
            if 'json' not in call:
                call['json'] = {}
            call['json'].update(json)
        if self.base_headers:
            if 'headers' not in call:
                call['headers'] = {}
            call['headers'].update(headers)
        if headers:
            if 'headers' not in call:
                call['headers'] = {}
            call['headers'].update(headers)
        if cookies:
            if 'cookies' not in call:
                call['cookies'] = {}
            call['cookies'].update(cookies)
        if filepaths:
            call['files'] = {}
            for filename, file_path in filepaths.items():
                call['files'][filename] = open(file_path, "rb")
        if self.base_timeout is not None:
            call['timeout'] = self.base_timeout
            if timeout:
                call['timeout'] = timeout

        # Handle retries
        while rest_tries > 0:
            try:
                self.pre_try_mixin(request=call, method=method, rest_tries=rest_tries, retry_pause_seconds=retry_pause_seconds, backoff_seconds=backoff_seconds, verbose=verbose, logger=logger)
                resp = getattr(requests, method)(**call)
                self.post_try_mixin(request=call, response=resp, method=method, rest_tries=rest_tries, retry_pause_seconds=retry_pause_seconds, backoff_seconds=backoff_seconds, verbose=verbose, logger=logger)
                if resp.ok:
                    return resp
                self.log_call(level='warning', message=f"Rest response status code: {resp.status_code}", logger=logger)
            except Exception as err:
                self.failed_call_mixin(request=call, err=err, method=method, rest_tries=rest_tries, retry_pause_seconds=retry_pause_seconds, backoff_seconds=backoff_seconds, verbose=verbose, logger=logger)
                if not allow_errors:
                    raise err

            # Resp was not ok
            rest_tries -= 1
            if rest_tries > 0:
                self.retry_mixin(request=call, response=resp, method=method, rest_tries=rest_tries, retry_pause_seconds=retry_pause_seconds, backoff_seconds=backoff_seconds, verbose=verbose, logger=logger)
                sleep(retry_pause_seconds)
                retry_pause_seconds += backoff_seconds
        if resp:
            return resp
        else:
            return None

    def get(self, *args, **kwargs):
        content = None
        resp = self.make_call(method='get', **kwargs)
        try:
            content = resp.json()
        except:
            self.not_json_serializable_mixin(request=kwargs, response=resp, content=content, *args, **kwargs)
        return resp, content

    def post(self, *args, **kwargs):
        content = None
        resp = self.make_call(method='post', **kwargs)
        try:
            content = resp.json()
        except:
            self.not_json_serializable_mixin(request=kwargs, response=resp, content=content, *args, **kwargs)
        return resp, content

    def put(self, *args, **kwargs):
        content = None
        resp = self.make_call(method='put', **kwargs)
        try:
            content = resp.json()
        except:
            self.not_json_serializable_mixin(request=kwargs, response=resp, content=content, *args, **kwargs)
        return resp, content

    def patch(self, *args, **kwargs):
        content = None
        resp = self.make_call(method='patch', **kwargs)
        try:
            content = resp.json()
        except:
            self.not_json_serializable_mixin(request=kwargs, response=resp, content=content, *args, **kwargs)
        return resp, content

    def delete(self, *args, **kwargs):
        content = None
        resp = self.make_call(method='delete', **kwargs)
        try:
            content = resp.json()
        except:
            self.not_json_serializable_mixin(request=kwargs, response=resp, content=content, *args, **kwargs)
        return resp, content

    def to_json(self):
        pass

    def from_json(self):
        pass

    def generate_request_json(self, method,  *args, **kwargs):
        """
        save_request_directory: str | None = None,
        redacted_keys: List[str] = ['Authorization']):
        """
        output = {
            'method': method,
            'url': kwargs.get('url'),
            'base_url': kwargs.get('base_url') or self.base_url,
            'endpoint': kwargs.get('endpoint'),
            'params': kwargs.get('params'),
            'data': kwargs.get('data'),
            'json': kwargs.get('json'),
            'body': kwargs.get('body'),
            'headers': kwargs.get('headers') or self.base_headers,
            'cookies': kwargs.get('cookies'),
            'filepaths': kwargs.get('filepaths'),
            # 'auth': kwargs.get('auth'),
            'timeout': kwargs.get('timeout') or self.base_timeout,
            # 'allow_redirects': kwargs.get('allow_redirects'),
            # 'proxies': kwargs.get('proxies'),
            # 'verify': kwargs.get('verify'),
            # 'stream': kwargs.get('stream'),
            # 'cert': kwargs.get('cert'),
            'rest_tries': kwargs.get('rest_tries') or self.rest_tries,
            'retry_pause_seconds': kwargs.get('retry_pause_seconds') or self.retry_pause_seconds,
            'backoff_seconds': kwargs.get('backoff_seconds') or self.backoff_seconds,
            'verbose': kwargs.get('verbose') or self.verbose,
            'allow_errors': kwargs.get('allow_errors'),
            'class_parameters': {
                'save_request_directory': self.save_request_directory,
                'redacted_keys': self.redacted_keys,
            },
        }

        output = self.generate_request_json_mixin(output=output)
        return output

    @classmethod
    def run_request_json(cls, dct):
        obj, dct = cls.run_request_json_mixin(dct=dct)
        method = dct.pop('method')
        return getattr(obj, method)(**dct)


    def sanitize(self):
        pass

    def log_call(self, level, message, logger=None):
        logger = logger or self.logger
        if logger:
            self.logger_mixin(level=level, message=message, logger=logger)
        else:
            print(message)

    def _mock_call(self):
        pass

    # MIXINS
    def pre_try_mixin(self, request, *args, **kwargs):
        pass

    def post_try_mixin(self, request, response, *args, **kwargs):
        pass

    def retry_mixin(self, request, response, *args, **kwargs):
        pass

    def failed_call_mixin(self, request, err, *args, **kwargs):
        pass

    def not_json_serializable_mixin(self, request, err, *args, **kwargs):
        pass

    def logger_mixin(self, level, message, logger):
        getattr(logger, level)(message)

    def generate_request_json_mixin(self, output):
        return output

    @classmethod
    def run_request_json_mixin(cls, dct):
        class_parameters = {k: v for k, v in dct.pop('class_parameters', {}).items() if v is not None}
        obj = cls(**class_parameters)
        return obj, dct


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


if __name__ == '__main__':
    x=1
    class MockLogger:
        def warning(self, *args, **kwargs):
            x=1
    test = PyRest(base_url='https://httpbin.org/get', retries=2)
    service = TestService(base_url='https://httpbin.org', retries=2, verbose=True, logger=MockLogger())
    # resp, content = test.get()
    # resp, content = service.get()
    # params = {'key': "value"}
    # resp, content = service.get(endpoint='get', params=params)
    # body = {'key': "value"}
    # resp, content = service.post(endpoint='post', json=body)
    # resp, content = service.post(endpoint='post', data=body)
    # files = 'txt.txt'
    # resp, content = service.post(endpoint='post', filepaths=files)
    # files = {'example_file': 'txt.txt'}
    # resp, content = service.post(endpoint='post', filepaths=files)
    # cookies = {'key': 'value'}
    # resp, content = service.post(endpoint='post', cookies=cookies)

    params = {'key': "value"}
    body = {'key': "value"}
    files = {'example_file': 'txt.txt'}
    cookies = {'key': 'value'}

    json_content = service.generate_request_json(
        method='post',
        endpoint='post',
        params=params,
        json=body,
        filepaths=files,
        cookies=cookies)
    rest, content = PyRest.run_request_json(json_content)

    x=1

"""
https://requests.readthedocs.io/en/latest/user/authentication/

import requests
class MyAuth(requests.auth.AuthBase):
    def __call__(self, r):
        # Implement my authentication
        return r

url = 'https://httpbin.org/get'
requests.get(url, auth=MyAuth())
"""

x=1


