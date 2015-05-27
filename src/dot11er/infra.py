#!/usr/bin/python

import functools

from scapy.all import *

from dot11er.util import frame, essid

def RX_FRAME_QUEUE(mon_if):
    """Return name of queue used for frames received on monitoring interface
    'mon_if'."""
    return "%s.rx_frame" % mon_if

def TX_FRAME_QUEUE(mon_if):
    """Return name of queue used for frames to be sent on monitoring
    interface 'mon_if'."""
    return "%s.tx_frame" % mon_if

def RX_BEACON_QUEUE(mon_if):
    """Return name of queue used for beacon frames received on monitoring
    interface 'mon_if'."""
    return "%s.rx_beacon" % mon_if

def RX_PROBE_QUEUE(mon_if):
    """Return name of queue used for probe request frames received on monitoring
    interface 'mon_if'."""
    return "%s.rx_probe_req" % mon_if

def TX_PROBE_QUEUE(mon_if):
    """Return name of queue used for sending out probe request on monitoring
    interface 'mon_if'."""
    return "%s.tx_probe" % mon_if

def RX_PROBE_RESP_QUEUE(mon_if):
    """Return name of queue used for probe response frames received on
    monitoring interface 'mon_if'."""
    return "%s.rx_probe_resp" % mon_if

def RX_AUTH_QUEUE(mon_if):
    """Return name of queue used for authentication frames received on
    monitoring interface 'mon_if'."""
    return "%s.rx_auth" % mon_if

def RX_ASSOC_QUEUE(mon_if):
    """Return name of queue used for association request frames received on
    monitoring interface 'mon_if'."""
    return "%s.rx_assoc_req" % mon_if

def RX_ASSOC_RESP_QUEUE(mon_if):
    """Return name of queue used for association response frames received on
    monitoring interface 'mon_if'."""
    return "%s.rx_assoc_resp" % mon_if

def RX_EAP_QUEUE(mon_if):
    """Return name of queue used for EAP frames received on monitoring interface
    'mon_if'."""
    return "%s.rx_eap" % mon_if

def AP_QUEUE(mon_if):
    """Return name of queue used for APs detected on monitoring interface
    'mon_if'."""
    return "%s.access_points" % mon_if

def ap_dump(r, mon_if):
    """Filter for APs and publish their ESSID and BSSID on
    'AP_QUEUE(mon_if)'."""
    # TODO Evaluate association requests to detect hidden SSIDs.
    # TODO The function follows a more general pattern to be abstracted.
    ps = r.pubsub()
    in_queue = RX_BEACON_QUEUE(mon_if)
    out_queue = AP_QUEUE(mon_if)
    ps.subscribe(in_queue)
    for m in ps.listen():
        f = frame(m)

        # TODO add sanity checks
        bssid = f.addr3
        if essid(f):
            r.publish(out_queue, (essid(f), bssid))
