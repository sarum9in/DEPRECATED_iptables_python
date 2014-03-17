#!/usr/bin/python3
# -*- coding: utf-8 -*-


class Option(object):

    """Base class for matcher options"""

    def __init__(self, option, value):
        self._option = option
        self._value = value
        self._negate = False

    def negate(self, negate=True):
        self._negate = negate
        return self

    def line(self):
        line = [self._option] + self._value
        if self._negate:
            return ["!"] + line
        else:
            return line

    def __eq__(self, option):
        return \
            type(self) == type(option) and \
            self.line() == option.line()


class Protocol(Option):

    def __init__(self, protocol):
        super(Protocol, self).__init__("--protocol", [protocol])


class Source(Option):

    def __init__(self, host):
        super(Source, self).__init__("--source", [host])


class Destination(Option):

    def __init__(self, host):
        super(Destination, self).__init__("--destination", [host])


class InInterface(Option):

    def __init__(self, interface):
        super(InInterface, self).__init__("--in-interface", [interface])


class OutInterface(Option):

    def __init__(self, interface):
        super(OutInterface, self).__init__("--out-interface", [interface])
