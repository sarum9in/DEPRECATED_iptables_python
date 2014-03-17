#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess


class IPTables(object):

    """Represent iptables instance"""

    def __init__(self):
        """Initializes Iptables object"""
        self._tables = ["filter", "nat", "mangle"]
        self._list = []
        self._debug = False
        self._silent = False
        self.set_command(["iptables"])

    def apply_rule(self, rule):
        """
            Apply specified rule using Iptables implementation
            External function
        """
        rule.apply(self)

    def add_rule(self, table, chain, rule):
        assert table
        assert chain
        self._list.append(["--table", table, "--append", chain] + rule)

    def add_raw_rule(self, table, rule):
        assert table
        self._list.append(["--table", table] + rule)

    def add_chain(self, table, chain):
        assert table
        assert chain
        self._list.append(["--table", table, "--new-chain", chain])

    def delete_chain(self, table, chain=None):
        assert table
        cmd = ["--table", table, "--delete-chain"]
        if chain:
            cmd.append(chain)
        self._list.append(cmd)

    def flush_chain(self, table, chain=None):
        cmd = ["--table", table, "--flush"]
        if chain:
            cmd.append(chain)
        self._list.append(cmd)

    def set_command(self, command):
        self._command = command

    def set_debug(self, value=True):
        """
            Set Iptables object to debug mode
            In this mode it will simply print everything to stdout
            instead of trying to do it
        """
        self._debug = value

    def set_silent(self, value=True):
        self._silent = value

    def set_normal(self):
        """Set Iptables object to normal mode"""
        self._debug = False

    def clear(self):
        """Clear Iptables tables and reset policies"""
        for i in self._tables:
            self.flush_chain(table=i)
            self.delete_chain(table=i)
        for i in ["INPUT", "FORWARD", "OUTPUT"]:
            self.apply_rule(Policy(chain=i, policy="ACCEPT"))

    def ip_forward(self, value=True):
        fmt = value and "1" or "0"
        if not self._silent:
            print("echo {} >/proc/sys/net/ipv4/ip_forward".format(fmt))
        if not self._debug:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(fmt)

    def commit(self):
        """
            Apply changes, all previous methods
            will only prepare things in memory
        """
        to_strlist = lambda x: list(map(str, x))
        for i in self._list:
            if not self._silent:
                print(" ".join(self._command + to_strlist(i)))
            if not self._debug:
                args = self._command + to_strlist(i)
                with subprocess.Popen(args) as cmd:
                    cmd.wait()

from iptables.option import *
from iptables.rule import *


class Policy(object):

    """Rule-like object that specifies default chain policy"""

    def __init__(self, chain, policy=None):
        self._chain = chain
        self._policy = policy

    def policy(self, policy):
        self._policy = policy
        return self

    def drop(self):
        return self.policy("DROP")

    def accept(self):
        return self.policy("ACCEPT")

    def reject(self):
        return self.policy("REJECT")

    def apply(self, iptables):
        iptables.add_raw_rule(
            table="filter",
            rule=["--policy", self._chain, self._policy]
        )

    def __repr__(self):
        return "Policy(chain={chain}, policy={policy})".format(
            chain=self._chain,
            policy=self._policy
        )

from iptables.match import *
