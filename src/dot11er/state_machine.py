#!/usr/bin/python

import ast,logging

from scapy.all import *

from dot11er.infra import *
from dot11er.util import essid,frames_in_scope

logger = logging.getLogger('dott11er.eap')

def sm(sta, bssid):
    return (sta, bssid)

def probe_request(r, mon_if):
    """Listen on 'probe_request' queue for requests to send out probes.
    Requests must have the form
    "{ 'sta'       : STATION MAC,
       'bssid'     : BSSID,
       'essid'     : ESSID}".

    ANY -- msg / probe req --> 'probing'"""

    # TODO improve rate handling
    rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],\
            info = Dot11InfoElt(information = "\x82\x84\x8b\x96\x24\x30\x48\x6c"))
#             info = Dot11InfoElt(information = "\x02\x04\x0b\x16"))

    ps = r.pubsub()
    ps.subscribe(TX_PROBE_QUEUE(mon_if))

    for m in ps.listen():
        req = ast.literal_eval(m['data'])
        sta = req['sta'].lower()
        bssid = req['bssid'].lower()
        essid = req['essid']

        logger.info("probing ESSID '%s'", essid, \
                extra = {'sta' : sta, 'bssid' : bssid})

        mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Probe Request'],\
                type = Dot11.TYPE_MANAGEMENT,\
                addr1 = bssid,
                addr2 = sta,
                addr3 = bssid)
        ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],\
                info = Dot11SSIDElt(SSID = essid))
        f = mgt/ssid/rates

        # remember state
        r.hset('state', sm(sta, bssid), 'probing')
        r.hset('essid', sm(sta, bssid), essid)

        r.publish(TX_FRAME_QUEUE(mon_if), f)

def authentication(r, mon_if, sta_list = None, auth = Dot11Auth(algo = "open", seqnum = 1)):
    """State transition on authentication:
    Performs authentication on received probe response.

    'probing' -- probe resp / auth --> 'authenticating'"""

    for f in frames_in_scope(r, RX_PROBE_RESP_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3

        if r.hget('state', sm(sta,bssid)) == 'probing':
            # TODO check for correct ESSID
            logger.debug("probing ESSID '%s' successful", essid, \
                    extra = {'sta' : sta, 'bssid' : bssid})
            logger.info("authenticating to ESSID '%s'", essid, \
                    extra = {'sta' : sta, 'bssid' : bssid})

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Authentication'],\
                    type = Dot11.TYPE_MANAGEMENT,\
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid)
            f = mgt/auth
        
            r.hset('state', sm(sta, bssid), 'authenticating')

            r.publish(TX_FRAME_QUEUE(mon_if), f)

def association(r, mon_if, sta_list = None, \
        assoc = Dot11AssoReq(cap = 0x3104), \
        rsn_info = Dot11Elt(ID = DOT11_INFO_ELT['RSN'], \
            info = Dot11RSNElt(
                PCS_List = [Dot11CipherSuite(Suite_Type = DOT11_CIPHER_SUITE_TYPE['CCMP'])],
                AKM_List = [Dot11AKMSuite(Suite_Type = DOT11_AKM_SUITE_SELECTOR['PSK'])]))
        ):
    """State transition on association:
    Performs association on successful received authentication.

    'authenticating' -- auth / assoc --> 'associating'"""

    # TODO improve rate handling
    rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],\
            info = Dot11InfoElt(information = "\x02\x04\x0b\x16"))

    for f in frames_in_scope(r, RX_AUTH_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', sm(sta,bssid))

        if r.hget('state', sm(sta,bssid)) == 'authenticating':
            # TODO check for successful auth
            # TODO check for correct ESSID
            logger.debug("authenticated to ESSID '%s'", essid, \
                    extra = {'sta' : sta, 'bssid' : bssid})
            logger.info("associating to ESSID '%s'", essid, \
                    extra = {'sta' : sta, 'bssid' : bssid})

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Association Request'],\
                    type = Dot11.TYPE_MANAGEMENT,\
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid)
            ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],\
                    info = Dot11SSIDElt(SSID = essid))
            f = mgt/assoc/ssid/rates/rsn_info

            r.hset('state', sm(sta, bssid), 'associating')

            r.publish(TX_FRAME_QUEUE(mon_if), f)

def eapol_start(r, mon_if, sta_list = None):
    """State transition on EAPOL start:
    Start EAPOL on successful association.
    'associating' -- associaton resp / EAPOL_start --> 'eapol_started'"""

    for f in frames_in_scope(r, RX_ASSOC_RESP_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3

        if r.hget('state', sm(sta,bssid)) == 'associating':
            # TODO check for successful association
            logger.debug("associated to ESSID '%s'", essid, \
                    extra = {'sta' : sta, 'bssid' : bssid})
            logger.info("starting EAPOL", extra = {'sta' : sta, 'bssid' : bssid})

            r.hset('state', sm(sta, bssid), 'eap')
            # TODO complete me

#            r.publish(TX_FRAME_QUEUE(mon_if), f)
