"""
Contains custom exceptions used to help distinguish emulation errors from
errors caused by bugs.
"""


class FunctionTracingError(Exception):
    def __init__(self, message, ip=None):
        super(FunctionTracingError, self).__init__(message)
        self.ip = ip

    def __str__(self):
        message = super(FunctionTracingError, self).__str__()
        if self.ip is not None:
            return "0x{:X} :: ".format(self.ip) + message
        else:
            return message
