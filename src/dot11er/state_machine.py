#!/usr/bin/python

import ast
from scapy.all import *

from dot11er.infra import *
from dot11er.util import essid,frames_in_scope

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

        # TODO introduce proper logging
        print "[+] probing ESSID '%s' / BSSID '%s' from STA '%s'" % (essid, bssid, sta)

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
            # TODO introduce proper logging
            print "[+] successfully probed (ESSID '%s', BSSID '%s')" % (essid(f), bssid)
            print "[*]     starting authentication"

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
            # TODO introduce proper logging
            print "[+] successfully authenticated (BSSID '%s')" % (bssid)
            print "[*]     associating"

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
            # TODO introduce proper logging
            print "[+] successfully associated (BSSID '%s')" % (bssid)
            print "[*]     starting EAPOL"

            r.hset('state', sm(sta, bssid), 'eap')
            # TODO complete me

#            r.publish(TX_FRAME_QUEUE(mon_if), f)
