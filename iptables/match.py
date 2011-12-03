#!/usr/bin/python3
# -*- coding: utf-8 -*-

from iptables.helper import *
from iptables.option import *

class Match(object):
	def __init__(self):
		self._attr = ["match", "args"]
		for i in self._attr:
			setattr(self, "_"+i, None)
	def match(self, match):
		"""Matcher, see iptables(8)"""
		self._match = match
		return self
	def args(self, args):
		self._args = args
		return self
	def arg(self, *args):
		if not self._args:
			self._args = []
		for i in args:
			self._args.append(i)
		return self
	def option(self, option):
		self.arg(*option.line())
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
	def __init__(self, protocol, sport=None, dport=None, sport_end=None, dport_end=None):
		super(MatchTCPUDP, self).__init__()
		self.match(protocol)
		if sport:
			self.arg("--source-port", create_range(":", sport, sport_end))
		if dport:
			self.arg("--destination-port", create_range(":", dport, dport_end))
	def setup(self, policy):
		policy.option(Protocol(self._match))

class MatchTCP(MatchTCPUDP):
	def __init__(self, **kwargs):
		super(MatchTCP, self).__init__("tcp", **kwargs)
	def tcp_flags(self, mask, comp):
		self.arg("--tcp-flags", mask, comp)
		return self

class MatchUDP(MatchTCPUDP):
	def __init__(self, **kwargs):
		super(MatchUDP, self).__init__("udp", **kwargs)

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
	def __init__(self, mss, mss_end=None):
		super(MatchTCPMSS, self).__init__()
		self.match("tcpmss").arg("--mss")
		mss_ = str(mss)
		if mss_end:
			mss_ += ":"+str(mss_end)
		self.arg(mss_)

__all__ = [
	"Match",
	"MatchTCPUDP",
	"MatchTCP",
	"MatchUDP",
	"MatchICMP",
	"MatchMAC",
	"MatchTCPMSS"
]

