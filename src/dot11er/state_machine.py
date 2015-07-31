#!/usr/bin/python

import ast,logging
from enum import Enum

from scapy.all import *

from dot11er.infra import *
import dot11er.util
from dot11er.util import frames_in_scope

logger = logging.getLogger('dott11er.eap')

# TODO change to proper enum
class State(Enum):
    unauthenticated  = 1
    authenticating   = 2
    associating      = 3
    associated       = 4

def init(r, sta, bssid):
    set_state(r, sta, bssid, State.unauthenticated, 0)

def get_state(r, sta, bssid):
    t = r.hget('state', (sta,bssid))
    if t:
        (st, sn) = ast.literal_eval(t)
        return (State(int(st)), int(sn))
    else:
        return (State.unauthenticated, 0)

def set_state(r, sta, bssid, st, sn):
    r.hset('state', (sta,bssid), (st.value, sn))

def probe_request(r, mon_if):
    """Listen on 'probe_request' queue for requests to send out probes.
    Requests must have the form
    "{ 'sta'       : STATION MAC,
       'bssid'     : BSSID,
       'essid'     : ESSID}"."""

    # TODO improve rate handling
    rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],
            info = Dot11InfoElt(information = "\x82\x84\x8b\x96\x24\x30\x48\x6c"))
#             info = Dot11InfoElt(information = "\x02\x04\x0b\x16"))

    ps = r.pubsub()
    ps.subscribe(TX_PROBE_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        req = ast.literal_eval(m['data'])
        sta = req['sta'].lower()
        bssid = req['bssid'].lower()
        essid = req['essid']
        (state, sn) = get_state(r, sta, bssid)

        logger.info("probing",
                extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

        mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Probe Request'],
                type = Dot11.TYPE_MANAGEMENT,
                addr1 = bssid,
                addr2 = sta,
                addr3 = bssid,
                SC = sn << 4)
        ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],
                info = Dot11SSIDElt(SSID = essid))
        f = mgt/ssid/rates

        set_state(r, sta, bssid, state, sn + 1)
        r.publish(TX_FRAME_QUEUE(mon_if), f)

def authentication(r, mon_if, sta_list = None, auth = Dot11Auth(algo = "open", seqnum = 1)):
    """State transition on authentication:
    Performs authentication on received probe response.
    """

    for f in frames_in_scope(r, RX_PROBE_RESP_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3
        essid = dot11er.util.essid(f)
        (state, sn) = get_state(r, sta, bssid)

        logger.debug("rx probe resp",
                extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

        # TODO check for correct ESSID

        if state == State.unauthenticated:
            logger.info("authenticating",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Authentication'],
                    type = Dot11.TYPE_MANAGEMENT,
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid,
                    SC = sn << 4)
            f = mgt/auth
            set_state(r, sta, bssid, State.authenticating, sn + 1)
            r.hset('essid', (sta, bssid), essid)
            r.publish(TX_FRAME_QUEUE(mon_if), f)

        elif state == State.authenticating:
            # check for retry
            if (f.FCfield & 8) >> 3:
                logger.debug("rx probe resp retry, tx auth req retry",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Authentication'],
                        type = Dot11.TYPE_MANAGEMENT,
                        FCfield = "retry",
                        addr1 = bssid,
                        addr2 = sta,
                        addr3 = bssid,
                        SC = (sn - 1) << 4)
            else:
                logger.debug("rx duplicate probe resp not marked as retry, resending auth req",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Authentication'],
                        type = Dot11.TYPE_MANAGEMENT,
                        addr1 = bssid,
                        addr2 = sta,
                        addr3 = bssid,
                        SC = sn << 4)
                set_state(r, sta, bssid, state, sn + 1)
            f = mgt/auth
#            r.publish(TX_FRAME_QUEUE(mon_if), f)

        else:
            logger.debug("rx probe resp while being authenticated",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})


def association(r, mon_if, sta_list = None, \
        assoc = Dot11AssoReq(cap = 0x3104), \
        rsn_info = Dot11Elt(ID = DOT11_INFO_ELT['RSN'], \
            info = Dot11RSNElt(
                PCS_List = [Dot11CipherSuite(Suite_Type = DOT11_CIPHER_SUITE_TYPE['CCMP'])],
                AKM_List = [Dot11AKMSuite(Suite_Type = DOT11_AKM_SUITE_SELECTOR['PSK'])]))
        ):
    """State transition on association:
    Performs association on successful received authentication.
    """

    # TODO improve rate handling
    rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],\
            info = Dot11InfoElt(information = "\x02\x04\x0b\x16"))

    for f in frames_in_scope(r, RX_AUTH_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', (sta,bssid))
        (state, sn) = get_state(r, sta, bssid)

        logger.debug("rx auth resp",
                extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

        ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],\
                info = Dot11SSIDElt(SSID = essid))

        if state == State.authenticating:
            # TODO check for successful auth
            logger.info("associating",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Association Request'],
                    type = Dot11.TYPE_MANAGEMENT,
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid,
                    SC = sn << 4)
            f = mgt/assoc/ssid/rates/rsn_info

            set_state(r, sta, bssid, State.associating, sn + 1)

            r.publish(TX_FRAME_QUEUE(mon_if), f)

        elif state == State.associating:
            # check for retry
            if (f.FCfield & 8) >> 3:
                logger.debug("rx auth resp retry, tx assoc req retry",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Association Request'],
                        type = Dot11.TYPE_MANAGEMENT,
                        FCfield = "retry",
                        addr1 = bssid,
                        addr2 = sta,
                        addr3 = bssid,
                        SC = (sn - 1) << 4)
            else:
                logger.debug("rx duplicate auth resp not marked as retry, resending assoc req",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Association Request'],
                        type = Dot11.TYPE_MANAGEMENT,
                        addr1 = bssid,
                        addr2 = sta,
                        addr3 = bssid,
                        SC = sn << 4)
                set_state(r, sta, bssid, state, sn + 1)
            f = mgt/assoc/ssid/rates/rsn_info
#            r.publish(TX_FRAME_QUEUE(mon_if), f)

        else:
            logger.warning("rx auth resp while neither authenticating nor associating",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

def eapol_start(r, mon_if, sta_list = None):
    """State transition on EAPOL start:
    Start EAPOL on successful association.
    """

    for f in frames_in_scope(r, RX_ASSOC_RESP_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', (sta,bssid))
        (state, sn) = get_state(r, sta, bssid)

        logger.debug("rx assoc resp",
                extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

        if state == State.associating:
            # TODO check for successful association

            logger.info("starting EAPOL",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

            set_state(r, sta, bssid, State.associated, sn)

            # TODO complete me

        elif state == State.associated:
            # check for retry
            if (f.FCfield & 8) >> 3:
                logger.debug("rx assoc resp retry, tx EAPOL start retry",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                # TODO complete me
            else:
                logger.debug("rx duplicate assoc resp not marked as retry, resending EAPOL start",
                        extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})
                # TODO complete me
        else:
            logger.warning("rx assoc resp while neither associating nor being associated",
                    extra = {'sta' : sta, 'bssid' : bssid, 'essid' : essid})

# TODO implement disassoc / deauth / reassoc
