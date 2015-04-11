#!/usr/bin/python

import ast
from scapy.all import *

from dot11er.infra import *
from dot11er.util import essid

def sm(sta, bssid):
    return (sta, bssid)

def probe_request(r):
    """Listen on 'probe_request' queue for requests to send out probes.
    Requests must have the form
    "{ 'interface' : MONITORING INTERFACE,
       'sta'       : STATION MAC,
       'bssid'     : BSSID,
       'essid'     : ESSID}"."""
    ps = r.pubsub()
    ps.subscribe('probe_request')
    for m in ps.listen():
        req = ast.literal_eval(m['data'])
        mon_if = req['interface']
        sta = req['sta']
        bssid = req['bssid']
        essid = req['essid']

        # TODO introduce proper logging
        print "[+] probing ESSID '%s' / BSSID '%s' from STA '%s'" % (essid, bssid, sta)

        mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Probe Request'],\
                type = Dot11.TYPE_MANAGEMENT,\
                addr1 = bssid,
                addr2 = sta,
                addr3 = bssid)
        ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],\
                SSID = Dot11SSIDElt(SSID = essid))
        # TODO improve rate handling
        rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],\
                information = Dot11InfoElt(information = "\x02\x04\x0b\x16"))
        f = mgt/ssid/rates

        # remember state
        r.hset('state', sm(sta, bssid), 'probing')
        r.hset('essid', sm(sta, bssid), essid)

        r.publish(TX_FRAME_QUEUE(mon_if), f)

def open_auth(r, mon_if):
    """State transition on open authentication:
    Perform open authentication on received probe response.
    'probing' -- probe_req / open auth --> 'authenticating'"""
    ps = r.pubsub()
    ps.subscribe(RX_PROBE_RESP_QUEUE(mon_if))

    for m in ps.listen():
        f = frame(m)

        sta = f.addr1
        bssid = f.addr3

        if r.hget('state', sm(sta,bssid)) == 'probing':
            # TODO check for correct ESSID
            # TODO introduce proper logging
            print "[+] successfully probed (ESSID '%s', BSSID '%s')" % (essid(f), bssid)
            print "[*]     starting open auth"

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Authentication'],\
                    type = Dot11.TYPE_MANAGEMENT,\
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid)
            auth = Dot11Auth(algo = "open", seqnum = 1)
            f = mgt/auth
        
            # remember state
            r.hset('state', sm(sta, bssid), 'authenticating')

            r.publish(TX_FRAME_QUEUE(mon_if), f)

def association(r, mon_if):
    """State transition on association:
    Perform association on successful authentication.
    'authenticating' -- auth / assoc --> 'associating'"""
    ps = r.pubsub()
    ps.subscribe(RX_AUTH_QUEUE(mon_if))

    for m in ps.listen():
        f = frame(m)

        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', sm(sta,bssid))

        if r.hget('state', sm(sta,bssid)) == 'authenticating':
            # TODO introduce proper logging
            print "[+] successfully authenticated (BSSID '%s')" % (bssid)
            print "[*]     associating"

            mgt = Dot11(subtype = Dot11.SUBTYPE['Management']['Association Request'],\
                    type = Dot11.TYPE_MANAGEMENT,\
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid)
            assoc = Dot11AssoReq(cap = 0x3104)
            ssid = Dot11Elt(ID = DOT11_INFO_ELT['SSID'],\
                    SSID = Dot11SSIDElt(SSID = essid))
            # TODO improve rate handling
            rates = Dot11Elt(ID = DOT11_INFO_ELT['Supported Rates'],\
                    information = Dot11InfoElt(information = "\x02\x04\x0b\x16"))
            # TODO improve RSN handling
            rsnInfo = Dot11Elt(ID = DOT11_INFO_ELT['RSN'],\
                    RSN = Dot11RSNElt(
                        PCS_List = [Dot11CipherSuite(Suite_Type = DOT11_CIPHER_SUITE_TYPE['CCMP'])],
                        AKM_List = [Dot11AKMSuite(Suite_Type = DOT11_AKM_SUITE_SELECTOR['IEEE802.1X'])]))
#                    AKM_List = [Dot11AKMSuite(Suite_Type = DOT11_AKM_SUITE_SELECTOR['PSK'])])

            f = mgt/assoc/ssid/rates/rsnInfo

            # remember state
            r.hset('state', sm(sta, bssid), 'associating')

            r.publish(TX_FRAME_QUEUE(mon_if), f)

def eapol_start(r, mon_if):
    """State transition on EAPOL start:
    Start EAPOL on successful association.
    'associating' -- assoc_resp / EAPOL_start --> 'eapol_started'"""
    ps = r.pubsub()
    ps.subscribe(RX_ASSOC_RESP_QUEUE(mon_if))

    for m in ps.listen():
        f = frame(m)

        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', sm(sta,bssid))

        if r.hget('state', sm(sta,bssid)) == 'associating':
            # TODO introduce proper logging
            print "[+] successfully associated (BSSID '%s')" % (bssid)
            print "[*]     starting EAPOL"

            # remember state
            r.hset('state', sm(sta, bssid), 'eapol_started')
            # TODO complete me

#            r.publish(TX_FRAME_QUEUE(mon_if), f)


def eap_id(r, mon_if):
    """State transition on EAP ID:
    Perform EAP ID on request.
    'eapol_started' -- EAP ID req / EAP ID resp --> 'eap_identified'"""
    ps = r.pubsub()
    ps.subscribe(RX_EAP_ID_QUEUE(mon_if))

    for m in ps.listen():
        f = frame(m)

        sta = f.addr1
        bssid = f.addr3
        essid = r.hget('essid', sm(sta,bssid))

        if r.hget('state', sm(sta,bssid)) == 'eapol_started':
            # TODO introduce proper logging
            print "[+] EAP ID (BSSID '%s')" % (bssid)

            mgt = Dot11(subtype = Dot11.SUBTYPE['Data']['Data'],\
                    type = Dot11.TYPE_DATA,\
                    FCfield = "to-DS",
                    addr1 = bssid,
                    addr2 = sta,
                    addr3 = bssid)

            # TODO improve EAP ID handling
            eap = EAP(code = EAP.RESPONSE, id = f[EAP].id, type = EAP.TYPE_ID)/"test@test.de"

            f = mgt/LLC()/SNAP()/EAPOL()/eap

            # remember state
            r.hset('state', sm(sta, bssid), 'eap_id')

            r.publish(TX_FRAME_QUEUE(mon_if), f)
