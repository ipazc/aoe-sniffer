from flask import request
from flasked import Flasked

class Root():
    def get(self):
        return request.remote_addr

flasked = Flasked()
flasked["/"] = Root
flasked.run()