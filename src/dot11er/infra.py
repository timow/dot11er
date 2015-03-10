#!/usr/bin/python

from scapy.all import *

from dot11er.util import frame

def RX_FRAME_QUEUE(mon_if):
    """Return name of queue used for frames received on monitoring interface
    'mon_if'."""
    return "%s.rx_frame" % mon_if

def rx_frame(r, mon_if):
    """Sniff monitoring interface 'mon_if' and publish received frames on queue
    'RX_FRAME_QUEUE(mon_if)'."""
    queue = RX_FRAME_QUEUE(mon_if)
    def pub(frame):
        r.publish(queue, frame)
    sniff(iface = mon_if, prn = pub)

def TX_FRAME_QUEUE(mon_if):
    """Return name of queue used for frames to be sent on monitoring
    interface 'mon_if'."""
    return "%s.tx_frame" % mon_if

def tx_frame(r, mon_if):
    """Transmit frames received from queue 'TX_FRAME_QUEUE(mon_if)' via
    monitoring interface 'mon_if'."""
    ps = r.pubsub()
    ps.subscribe(TX_FRAME_QUEUE(mon_if))
    for m in ps.listen():
        sendp(frame(m), iface = mon_if)

def RX_BEACON_QUEUE(mon_if):
    """Return name of queue used for beacon frames received on monitoring
    interface 'mon_if'."""
    return "%s.rx_beacon" % mon_if

def rx_beacon(r, mon_if):
    """Filter for beacon frames and publish them on queue
    'RX_BEACON_QUEUE(mon_if)'."""
    # TODO The function follows a more general pattern to be abstracted.
    ps = r.pubsub()
    in_queue = RX_FRAME_QUEUE(mon_if)
    out_queue = RX_BEACON_QUEUE(mon_if)
    ps.subscribe(in_queue)
    for m in ps.listen():
        f = frame(m)
        # TODO add more reasonable sanity checks
        if f.type == Dot11.TYPE_MANAGEMENT and \
                f.subtype == Dot11.SUBTYPE["Management"]["Beacon"]:
            r.publish(out_queue, f)

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
        if f.haslayer(Dot11SSIDElt):
            essid = f[Dot11SSIDElt].SSID
            r.publish(out_queue, (essid, bssid))
