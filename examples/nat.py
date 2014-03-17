#!/usr/bin/python3
# -*- coding: utf-8 -*-

from iptables.profile import *


iptables = IPTables()
iptables.set_debug()

router = Router(
    iptables=iptables,
    local_ip=None,
    local_iface="internal",
    local_net="192.168.0.0/24",
    inet_ip=None,
    inet_iface="external"
)
router.set_tcpmss()
router.masquerade()
router.commit()
