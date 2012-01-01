#!/usr/bin/python3
# -*- coding: utf-8 -*-

def _create_range(joiner, *args):
	return joiner.join(map(str, filter(lambda x: x, args)))

__all__ = [
	"_create_range"
]

