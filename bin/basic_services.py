#!/usr/bin/python

import sys
import redis

from dot11er.infra import *
from dot11er.state_machine import probe_request
from dot11er.util import start_process, default_arg_parser, redis_obj

if __name__ == '__main__':
    parser = default_arg_parser()
    parser.description = 'Run basic services (frame-to-queue dispatch, probe request).'
    args = parser.parse_args()

    p_rx_dispatcher = start_process(rx_dispatcher, \
            (redis_obj(args), args.mon_if))
    p_rx_eap_dispatcher = start_process(rx_eap_dispatcher, \
            (redis_obj(args), args.mon_if))
    p_probe_request = start_process(probe_request, \
            (redis_obj(args), args.mon_if))

    p_rx_dispatcher.join()
    p_rx_eap_dispatcher.join()
    p_probe_request.join()
