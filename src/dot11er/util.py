#!/usr/bin/python

import multiprocessing

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

