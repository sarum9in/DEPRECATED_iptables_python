#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess

class Firewall(object):
	"""Represent iptables instance"""
	def __init__(self):
		"""Initializes firewall object"""
		self._tables = ["filter", "nat", "mangle"]
		self._list = []
		self._debug = False
		self.set_command(["iptables"])
	def apply_rule(self, rule):
		"""
			Apply specified rule using firewall implementation
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
			Set firewall object to debug mode
			In this mode it will simply print everything to stdout
			instead of trying to do it
		"""
		self._debug = True
	def set_normal(self):
		"""Set firewall object to normal mode"""
		self._debug = False
	def clear(self):
		"""Clear firewall tables and reset policies"""
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
				print(" ".join(self._command+i))
			else:
				with subprocess.Popen(self._command+i) as cmd:
					cmd.wait()

class Rule(object):
	"""Represents iptables rule"""
	def __init__(self):
		self._attr = ["table", "chain", "protocol", "source", "destination", "jump", "in_interface", "out_interface", "tail_range", "tail", "match"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def protocol(self, protocol, negate=False):
		self._protocol = protocol, negate
		return self
	def source(self, source, negate=False):
		self._source = source, negate
		return self
	def destination(self, destination, negate=False):
		self._destination = destination, negate
		return self
	def jump(self, jump):
		self._jump = jump
		return self
	#def goto(self, goto):
	#	self._goto = goto
	#	return self
	def in_interface(self, in_interface, negate=False):
		self._in_interface = in_interface, negate
		return self
	def out_interface(self, out_interface, negate=False):
		self._out_interface = out_interface, negate
		return self
	def match(self, matcher):
		matcher.setup(self)
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
	def apply(self, firewall):
		rule = []
		for i in ["protocol", "source", "destination", "in-interface", "out-interface"]:
			attr = getattr(self, "_"+i.replace("-", "_"))
			if attr:
				value, negate = attr
				if negate:
					rule += ["!"]
				rule += ["--{}".format(i), value]
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

class Policy(object):
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
	def apply(self, firewall):
		firewall.add_raw_rule(table="filter", rule=["--policy", self._chain, self._policy])
	def __repr__(self):
		return "Policy(chain={chain}, policy={policy})".format(chain=self._chain, policy=self._policy)

class Match(object):
	def __init__(self):
		self._attr = ["match", "args"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def match(self, m):
		"""Matcher, see iptables(8)"""
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
	def setup(self, policy):
		"""
			Will be called by policy, used to set up policy object
			Default implementation does nothing
		"""
		pass

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
	def setup(self, policy):
		policy.protocol("tcp")

class MatchUDP(MatchTCPUDP):
	def __init__(self, sport=None, dport=None):
		super(MatchUDP, self).__init__("udp", sport=sport, dport=dport)
	def setup(self, policy):
		policy.protocol("udp")

class MatchICMP(Match):
	def __init__(self, icmp_type):
		super(MatchICMP, self).__init__()
		self.match("icmp").arg("--icmp-type", icmp_type)
	def setup(self, policy):
		policy.protocol("icmp")

class MatchMAC(Match):
	def __init__(self, mac_source):
		super(MatchMAC, self).__init__()
		self.match("mac").arg("--mac-source", mac_source)

__all__ = [
	"Firewall",
	"Rule",
	"DNAT",
	"SNAT",
	"MASQUERADE",
	"ACCEPT",
	"ACCEPT_INPUT",
	"DROP",
	"REJECT",
	"Policy",
	"Match",
	"MatchTCPUDP",
	"MatchTCP",
	"MatchUDP",
	"MatchICMP",
	"MatchMAC"
]

