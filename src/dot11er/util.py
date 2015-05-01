#!/usr/bin/python

import argparse, multiprocessing

from scapy.all import RadioTap,Dot11Elt,DOT11_INFO_ELT

def start_process(func, args = ()):
    p = multiprocessing.Process(target = func, args = args)
    p.start()
    return p

def frame(redis_msg):
    return RadioTap(redis_msg['data'])

def essid(frame):
    for e in frame[Dot11Elt]:
        if e.ID == DOT11_INFO_ELT['SSID']:
            return e.SSID.SSID
    return None

def simple_filter(r, mon_if, IN_QUEUE, OUT_QUEUE, filt):
    ps = r.pubsub()
    in_queue = IN_QUEUE(mon_if)
    out_queue = OUT_QUEUE(mon_if)
    ps.subscribe(in_queue)
    for m in ps.listen():
        f = frame(m)
        if filt(f):
            r.publish(out_queue, f)

def default_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mon_if', default = 'mon0', \
            help = 'WLAN monitoring interface (default: mon0)')
    parser.add_argument('--redis_host', default = '127.0.0.1', \
            help = 'redis server hostname (default: 127.0.0.1)')
    parser.add_argument('--redis_port', default = 6379, type = int, \
            help = 'redis server port (default: 6379)')
    parser.add_argument('--redis_db', default = 0, type = int, \
            help = 'redis db (default: 0)')
    return parser
