#!/usr/bin/python3
# -*- coding: utf-8 -*-

from option import *

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
	def __eq__(self, match):
		return type(self)==type(match) and self.match_line()==match.match_line()

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
		policy.option(Protocol("tcp"))

class MatchUDP(MatchTCPUDP):
	def __init__(self, sport=None, dport=None):
		super(MatchUDP, self).__init__("udp", sport=sport, dport=dport)
	def setup(self, policy):
		policy.option(Protocol("udp"))

class MatchICMP(Match):
	def __init__(self, icmp_type):
		super(MatchICMP, self).__init__()
		self.match("icmp").arg("--icmp-type", icmp_type)
	def setup(self, policy):
		policy.option(Protocol("icmp"))

class MatchMAC(Match):
	def __init__(self, mac_source):
		super(MatchMAC, self).__init__()
		self.match("mac").arg("--mac-source", mac_source)

class MatchTCPMSS(Match):
	def __init__(self, mss):
		super(MatchTCPMSS, self).__init__()
		self.match("tcpmss").arg("--mss", mss)

__all__ = [
	"Match",
	"MatchTCPUDP",
	"MatchTCP",
	"MatchUDP",
	"MatchICMP",
	"MatchMAC"
]

