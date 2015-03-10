#!/usr/bin/python

import multiprocessing

from scapy.all import RadioTap

def start_process(func, args = ()):
    p = multiprocessing.Process(target = func, args = args)
    p.start()
    return p

def frame(redis_msg):
    return RadioTap(redis_msg['data'])
