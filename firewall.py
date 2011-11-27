#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess

class Firewall(object):
	def __init__(self):
		"""Initializes firewall object"""
		self._tables = ["filter", "nat", "mangle"]
		self.set_command(["iptables"])
		self._list = []
	def apply_rule(self, rule):
		"""Apply specified rule using firewall implementation"""
		"""External function"""
		rule.apply(self)
	def add_rule(self, table, chain, rule):
		self._list.append(self._command+["--table", table, "--append", chain]+rule)
	def add_raw_rule(self, table, rule):
		self._list.append(self._command+["--table", table]+rule)
	def add_chain(self, table, chain):
		self._list.append(self._command+["--table", table, "--new-chain", chain])
	def delete_chain(self, table, chain=None):
		cmd = self._command+["--table", table, "--delete-chain"]
		if chain:
			cmd.append(chain)
		self._list.append(cmd)
	def flush_chain(self, table, chain=None):
		cmd = self._command+["--table", table, "--flush-chain"]
		if chain:
			cmd.append(chain)
		self._list.append(cmd)
	def set_command(self, command):
		self._command = command
	def set_debug(self):
		self.set_command(["echo", "iptables"])
	def clear(self):
		for i in self._tables:
			self.delete_chain(table=i)
			self.flush_chain(table=i)
		for i in ["INPUT", "FORWARD", "OUTPUT"]:
			self.apply_rule(Policy(chain=i, policy="ACCEPT"))
	def commit(self):
		for i in self._list:
			with subprocess.Popen(i) as cmd:
				cmd.wait()

class Rule(object):
	def __init__(self):
		self._attr = ["table", "chain", "protocol", "source", "destination", "jump", "in_interface", "out_interface", "tail_range", "tail", "match"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def protocol(self, p):
		self._protocol = p
		return self
	def source(self, s):
		self._source = s
		return self
	def destination(self, d):
		self._destination = d
		return self
	def jump(self, j):
		self._jump = j
		return self
	#def goto(self, g):
	#	self._goto = g
	#	return self
	def in_interface(self, i, negate):
		self._in_interface = i, negate
		return self
	def out_interface(self, o, negate):
		self._out_interface = o, negate
		return self
	def match(self, matcher):
		if not self._match:
			self._match = []
		self._match.append(matcher)
		return self
	def tail_range(self, ipaddr=None, port=None, ipaddr_end=None, port_end=None):
		iprange = ipaddr and str(ipaddr) or None
		if ipaddr_end:
			assert iprange
			iprange = ipaddr+"-"+str(ipaddr_end)
		prange = port and str(port) or None
		if port_end:
			assert prange
			prange = prange+"-"+str(port_end)
		if iprange and prange:
			self.tail(["{}:{}".format(iprange, prange)])
		elif iprange:
			self.tail([iprange])
		elif prange:
			self.tail([prange])
		return self
	def tail(self, t):
		if not self._tail:
			self._tail = []
		self._tail += t
		return self
	def table(self, t):
		self._table = t
		return self
	def chain(self, c):
		self._chain = c
		return self
	def apply(self, firewall):
		rule = []
		if self._protocol:
			rule += ["--protocol", self._protocol]
		if self._source:
			rule += ["--source", self._source]
		if self._destination:
			rule += ["--destination", self._destination]
		if self._in_interface:
			iface, neg = self._in_interface
			if neg:
				rule.append("!")
			rule += ["--in-interface", iface]
		if self._out_interface:
			iface, neg = self._out_interface
			if neg:
				rule.append("!")
			rule += ["--out-interface", iface]
		if self._match:
			for i in self._match:
				rule += i.match_line()
		if self._jump:
			rule += ["--jump", self._jump]
		if self._tail:
			rule += self._tail
		firewall.add_rule(table=self._table, chain=self._chain, rule=rule)

class DNAT(Rule):
	# TODO random, persistent
	def __init__(self, ipaddr=None, port=None, ipaddr_end=None, port_end=None):
		super(DNAT, self).__init__()
		self.table("nat").chain("PREROUTING")
		self.jump("DNAT")
		self.tail(["--to-destination"])
		self.tail_range(ipaddr, port, ipaddr_end, port_end)

class SNAT(Rule):
	# TODO random, persistent
	def __init__(self, ipaddr=None, port=None, ipaddr_end=None, port_end=None):
		super(SNAT, self).__init__()
		self.table("nat").chain("POSTROUTING")
		self.jump("SNAT")
		self.tail(["--to-source"])
		self.tail_range(ipaddr, port, ipaddr_end, port_end)

class MASQUERADE(Rule):
	# TODO to-ports
	def __init__(self):
		super(MASQUERADE, self).__init__()
		self.table("nat").chain("POSTROUTING")
		self.jump("MASQUERADE")

class ACCEPT(Rule):
	def __init__(self):
		super(ACCEPT, self).__init__()
		self.jump("ACCEPT")

class ACCEPT_INPUT(ACCEPT):
	def __init__(self):
		super(ACCEPT_INPUT, self).__init__()
		self.table("filter").chain("INPUT")

class DROP(Rule):
	def __init__(self):
		super(DROP, self).__init__()
		self.jump("DROP")

class REJECT(Rule):
	def __init__(self, reject_with=None):
		super(REJECT, self).__init__()
		if reject_with:
			self.tail(["--reject-with", reject_with])
		self.jump("REJECT")

class Policy(object):
	def __init__(self, chain, policy):
		self._chain = chain
		self._policy = policy
	def apply(self, firewall):
		firewall.add_raw_rule(table="filter", rule=["--policy", self._chain, self._policy])

class Match(object):
	def __init__(self):
		self._attr = ["match", "args"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def match(self, m):
		self._match = m
		return self
	def args(self, a):
		self._args = a
		return self
	def arg(self, *a):
		if not self._args:
			self._args = []
		for i in a:
			self._args.append(i)
		return self
	def match_line(self):
		args = self._args
		if not args:
			args = []
		return ["-m", self._match]+args

class MatchTCPUDP(Match):
	def __init__(self, protocol, sport=None, dport=None):
		super(MatchTCPUDP, self).__init__()
		self.match(protocol)
		if sport:
			self.arg("--source-port", str(sport))
		if dport:
			self.arg("--destination-port", str(dport))

class MatchTCP(MatchTCPUDP):
	def __init__(self, sport=None, dport=None):
		super(MatchTCP, self).__init__("tcp", sport=sport, dport=dport)

class MatchUDP(MatchTCPUDP):
	def __init__(self, sport=None, dport=None):
		super(MatchUDP, self).__init__("udp", sport=sport, dport=dport)

__all__ = ["Firewall", "Rule", "DNAT", "SNAT", "MASQUERADE", "ACCEPT", "ACCEPT_INPUT", "DROP", "REJECT", "Policy", "Match", "MatchTCPUDP", "MatchTCP", "MatchUDP"]

