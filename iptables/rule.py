#!/usr/bin/python3
# -*- coding: utf-8 -*-

from iptables.option import *

class Rule(object):
	"""Represents iptables rule"""
	def __init__(self):
		self._attr = ["table", "chain", "jump", "tail_range", "tail", "option", "match"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def jump(self, jump):
		self._jump = jump
		return self
	#def goto(self, goto):
	#	self._goto = goto
	#	return self
	def protocol(self, protocol):
		return self.option(Protocol(protocol))
	def source(self, host):
		return self.option(Source(host))
	def destination(self, host):
		return self.option(Destination(host))
	def option(self, option):
		if not self._option:
			self._option = []
		if option not in self._option:
			self._option.append(option)
		return self
	def match(self, match):
		match.setup(self)
		if not self._match:
			self._match = []
		if match not in self._match:
			self._match.append(match)
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
	def tail(self, tail):
		if not self._tail:
			self._tail = []
		self.table("filter")
		self._tail += tail
		return self
	def table(self, table):
		self._table = table
		return self
	def chain(self, chain):
		self._chain = chain
		return self
	def apply(self, iptables):
		rule = []
		if self._option:
			for i in self._option:
				rule += i.line()
		if self._match:
			for i in self._match:
				rule += i.match_line()
		if self._jump:
			rule += ["--jump", self._jump]
		if self._tail:
			rule += self._tail
		iptables.add_rule(table=self._table, chain=self._chain, rule=rule)

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
		self.table("filter")
		self.jump("ACCEPT")

class ACCEPT_INPUT(ACCEPT):
	def __init__(self):
		super(ACCEPT_INPUT, self).__init__()
		self.chain("INPUT")

class ACCEPT_FORWARD(ACCEPT):
	def __init__(self):
		super(ACCEPT_INPUT, self).__init__()
		self.chain("FORWARD")

class ACCEPT_OUTPUT(ACCEPT):
	def __init__(self):
		super(ACCEPT_INPUT, self).__init__()
		self.chain("OUTPUT")

class DROP(Rule):
	def __init__(self):
		super(DROP, self).__init__()
		self.table("filter")
		self.jump("DROP")

class REJECT(Rule):
	def __init__(self, reject_with=None):
		super(REJECT, self).__init__()
		if reject_with:
			self.tail(["--reject-with", reject_with])
		self.table("filter")
		self.jump("REJECT")

class TCPMSS(Rule):
	def __init__(self):
		super(TCPMSS, self).__init__()
		self.table("filter").chain("FORWARD")
		self.option(Protocol("tcp"))
		self.jump("TCPMSS")
		self._inited = False
	def mss(self, mss):
		assert not self._inited
		self.tail(["--set-mss", mss])
		self._inited = True
		return self
	def clamp_mss_to_pmtu(self):
		assert not self._inited
		self.tail(["--clamp-mss-to-pmtu"])
		self._inited = True
		return self

__all__ = [
	"Rule",
	"DNAT",
	"SNAT",
	"MASQUERADE",
	"ACCEPT",
	"ACCEPT_INPUT",
	"DROP",
	"REJECT",
	"TCPMSS"
]

