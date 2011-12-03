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
		self._list.append(["--table", table, "--append", chain]+rule)
	def add_raw_rule(self, table, rule):
		assert table
		self._list.append(["--table", table]+rule)
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
		cmd = ["--table", table, "--flush-chain"]
		if chain:
			cmd.append(chain)
		self._list.append(cmd)
	def set_command(self, command):
		self._command = command
	def set_debug(self):
		"""
			Set Iptables object to debug mode
			In this mode it will simply print everything to stdout
			instead of trying to do it
		"""
		self._debug = True
	def set_normal(self):
		"""Set Iptables object to normal mode"""
		self._debug = False
	def clear(self):
		"""Clear Iptables tables and reset policies"""
		for i in self._tables:
			self.delete_chain(table=i)
			self.flush_chain(table=i)
		for i in ["INPUT", "FORWARD", "OUTPUT"]:
			self.apply_rule(Policy(chain=i, policy="ACCEPT"))
	def ip_forward(self):
		if self._debug:
			print("echo 1 >/proc/sys/net/ipv4/ip_forward")
		else:
			with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
				f.write("1")
	def commit(self):
		"""Apply changes, all previous methods will only prepare things in memory"""
		for i in self._list:
			if self._debug:
				print(" ".join(self._command+list(map(str, i))))
			else:
				with subprocess.Popen(self._command+i) as cmd:
					cmd.wait()

from iptables.option import *
from iptables.rule import *

class Policy(object):
	"""Rule-like object that specifies default chain policy"""
	def __init__(self, chain, policy=None):
		self._chain = chain
		self._policy = policy
	def drop(self):
		self._policy = "DROP"
		return self
	def accept(self):
		self._policy = "ACCEPT"
		return self
	def reject(self):
		self._policy = "REJECT"
		return self
	def apply(self, iptables):
		iptables.add_raw_rule(table="filter", rule=["--policy", self._chain, self._policy])
	def __repr__(self):
		return "Policy(chain={chain}, policy={policy})".format(chain=self._chain, policy=self._policy)

from iptables.match import *

__all__ = [
	"IPTables",
# Rules
	"Rule",
	"DNAT",
	"SNAT",
	"MASQUERADE",
	"ACCEPT",
	"ACCEPT_INPUT",
	"DROP",
	"REJECT",
	"TCPMSS",
	"Policy",
# Matches
	"Match",
	"MatchTCPUDP",
	"MatchTCP",
	"MatchUDP",
	"MatchICMP",
	"MatchMAC",
	"MatchTCPMSS",
# Options
	"Option",
	"Protocol",
	"Source",
	"Destination",
	"InInterface",
	"OutInterface"
]

