#!/usr/bin/python

import argparse, multiprocessing

import redis
from scapy.all import RadioTap,Dot11Elt,DOT11_INFO_ELT

LOG_FORMAT = '%(name)s:%(levelname)s:%(message)s (%(sta)s, %(bssid)s)'

def start_process(func, args = (), kwargs = {}):
    p = multiprocessing.Process(target = func, args = args, kwargs = kwargs)
    p.start()
    return p

def frame(redis_msg):
    return RadioTap(redis_msg['data'])

def frames_in_scope(r, queue, sta_list = None):
    ps = r.pubsub()
    ps.subscribe(queue)

    for m in ps.listen():
        f = frame(m)

        sta = f.addr1

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        yield f

def essid(frame):
    i = 1
    e = frame.getlayer(Dot11Elt, i)
    while e:
        if e.ID == DOT11_INFO_ELT['SSID']:
            return e.info.SSID
        i += 1
        e = frame.getlayer(Dot11Elt, i)
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

def redis_obj(args):
    return redis.StrictRedis(args.redis_host, args.redis_port, args.redis_db)
