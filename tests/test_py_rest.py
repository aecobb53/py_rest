from py_rest import PyRest, TestService

def test_py_rest():
    svc = PyRest()
    assert svc is not None

class MockLogger:
    def warning(self, *args, **kwargs):
        x=1
