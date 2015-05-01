#!/usr/bin/python

import sys
import redis

from dot11er.infra import *
from dot11er.util import start_process, default_arg_parser

if __name__ == '__main__':
    parser = default_arg_parser()
    parser.description = 'Run basic services (frame-to-queue dispatch, probe request).'
    args = parser.parse_args()

    p_rx_dispatcher = start_process(rx_dispatcher, ( \
            redis.StrictRedis(args.redis_host, args.redis_port, args.redis_db), \
            args.mon_if))
    p_rx_eap_dispatcher = start_process(rx_eap_dispatcher, ( \
            redis.StrictRedis(args.redis_host, args.redis_port, args.redis_db), \
            args.mon_if))
    p_probe_request = start_process(probe_request, ( \
            redis.StrictRedis(args.redis_host, args.redis_port, args.redis_db), \
            args.mon_if))

    p_rx_dispatcher.join()
    p_rx_eap_dispatcher.join()
    p_probe_request.join()
