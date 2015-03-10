#!/usr/bin/python

import sys
import redis

from dot11er.infra import rx_frame,tx_frame
from dot11er.util import start_process

if __name__ == '__main__':
    
    # TODO add appropriate cmd line parsing
    mon_if = sys.argv[1]

    redis_host = 'localhost'
    redis_port = 6379
    redis_db   = 0

    p_tx_frame = start_process(tx_frame, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))
    p_rx_frame = start_process(rx_frame, ( \
            redis.StrictRedis(redis_host, redis_port, redis_db), \
            mon_if))

    p_rx_frame.join()
    p_tx_frame.join()
