#!/usr/bin/python3
# -*- coding: utf-8 -*-

from iptables import *

class Profile(object):
	def __init__(self, iptables):
		self._iptables = iptables
		self._rules = []
	def add_rule(self, rule):
		self._rules.append(rule)
	def commit(self):
		self._iptables.clear()
		for i in self._rules:
			self._iptables.apply_rule(i)
		self._iptables.ip_forward(False)
		self._iptables.commit()
		self._iptables.ip_forward(True)

class Router(Profile):
	"""
		Profile for router-like servers
		iptables -- IPTables instance
		local_ip -- ip in LAN (may be None if unknown)
		local_iface -- interface for LAN
		local_net -- LAN netmask
		inet_ip -- external ip (may be NOne if unknown)
		inet_iface -- external interface
	"""
	def __init__(self, iptables, local_ip, local_iface, local_net, inet_ip, inet_iface):
		super(Router, self).__init__(iptables)
		self._local_ip = local_ip
		self._local_iface = local_iface
		self._local_net = local_net
		self._inet_ip = inet_ip
		self._inet_iface = inet_iface
	def policy(self, chain=None, policy=None):
		"""
			if chain and policy are None, default policies will be set up
			else chain and policy have to be string object
			and such policy will be applied
		"""
		if (not chain) and (not policy):
			for i in ["INPUT", "FORWARD"]:
				# POLICIES
				self.add_rule( Policy(chain=i).drop() )
				# TRUSTED OUTCOMING
				self.add_rule( ACCEPT().chain(i).option(InInterface(self._inet_iface)).match(MatchState("RELATED", "ESTABLISHED")) )
				# TRUSTED LAN
				self.add_rule( ACCEPT().chain(i).option(InInterface(self._inet_iface).negate()) )
		else:
			assert chain and policy
			add_rule( Policy(chain=chain, policy=policy) )
	def add_drop(self, source):
		for i in ["INPUT", "FORWARD", "OUTPUT"]:
			add_rule( DROP().source(source).chain(i) )
	def add_drop_string(self, source):
		"""
			Usage: add_drop_string("1.2.3.4 4.3.2.1")
		"""
		for i in source.split():
			add_drop(i)
	def set_tcpmss(self):
		# TODO investigate
		self.add_rule( TCPMSS().mss(1380).match(MatchTCP().tcp_flags("SYN,RST", "SYN")).match(MatchTCPMSS(1201, 6000)) )
		#self.add_rule( TCPMSS().clamp_mss_to_pmtu().match(MatchTCP().tcp_flags("SYN,RST", "SYN")) )
	def accept_input(self, match, ranges):
		"""
			Open server ports
			Usage: accept_input(MatchTCP(dport=1234), [1, 2, 3, (3, 10), 15])
			Usage: accept_input(MatchTCP(dport=1234), [1, 2, 3, [3, 10], 15])
		"""
		for i in ranges:
			if type(i) is tuple or type(i) is list:
				assert len(i)==2
				self.add_rule( ACCEPT_INPUT().match(match(dport=i[0], dport_end=i[1])) )
			else:
				self.add_rule( ACCEPT_INPUT().match(match(dport=i)) )
	def accept_input_string(self, match, strseq, delim="-"):
		"""
			Usage: accept_input_string(MatchTCP, "1 2 3 4-50", delim="-")
		"""
		self.accept_input(match, map(lambda x: x.split(delim) if delim in x else x, strseq.split()))
	def add_forward(self, ipaddr, port, match):
		for iface, ip in [(self._inet_iface, self._inet_ip), (self._local_iface, self._local_ip)]:
			dnat = DNAT(ipaddr=ipaddr, port=port).match(match).option(InInterface(iface))
			if ip:
				dnat.destination(ip)
			self.add_rule( dnat )
			self.add_rule( ACCEPT().chain("FORWARD").match(match).option(InInterface(iface)) )
	def masquerade(self):
		if self._inet_ip:
			self.add_rule(	SNAT(ipaddr=self._inet_ip).
					option(OutInterface(self._inet_iface)).
					option(Destination(self._local_net).negate()).
					source(self._local_net) )
		else:
			self.add_rule(	MASQUERADE().
					option(OutInterface(self._inet_iface)).
					option(Destination(self._local_net).negate()).
					source(self._local_net) )

