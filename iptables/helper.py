#!/usr/bin/python3
# -*- coding: utf-8 -*-

def create_range(joiner, *args):
	return joiner.join(map(str, filter(lambda x: x, args)))

__all__ = [
	"create_range"
]

