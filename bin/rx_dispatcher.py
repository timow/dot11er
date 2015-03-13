#!/usr/bin/python

import sys
import redis

from dot11er.infra import *
from dot11er.util import start_process

if __name__ == '__main__':
    
    # TODO add appropriate cmd line parsing
    mon_if = sys.argv[1]

    redis_host = 'localhost'
    redis_port = 6379
    redis_db   = 0

    p_rx_dispatcher = start_process(rx_dispatcher, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))
    p_rx_eap_dispatcher = start_process(rx_eap_dispatcher, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))

    p_rx_dispatcher.join()
    p_rx_eap_dispatcher.join()
