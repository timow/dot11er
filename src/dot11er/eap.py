#!/usr/bin/python

import ast,logging

from scapy.all import *

from dot11er.infra import *
from dot11er.state_machine import get_state, set_state
from dot11er.util import frames_in_scope

logger = logging.getLogger('dott11er.eap')

def RX_EAP_FRAME_QUEUE(mon_if):
    """Return name of queue used for EAP frames received on monitoring interface
    'mon_if'."""
    return "%s.rx_eap_frame" % mon_if

def TX_PEER_EAP_QUEUE(mon_if):
    """Return name of queue used for EAP messages to be send as a peer on
    monitoring interface 'mon_if'."""
    return "%s.tx_peer_eap" % mon_if

def RX_PEER_EAP_ID_QUEUE(mon_if):
    """Return name of queue used for EAP ID messages received for a peer on
    monitoring interface 'mon_if'."""
    return "%s.rx_peer_eap_id" % mon_if

def RX_PEER_EAP_PEAP_QUEUE(mon_if):
    """Return name of queue used for EAP PEAP messages received for a peer on
    monitoring interface 'mon_if'."""
    return "%s.rx_peer_peap_tls" % mon_if

def TX_PEER_EAP_PEAP_QUEUE(mon_if):
    """Return name of queue used for EAP PEAP messages to be send as a peer on
    monitoring interface 'mon_if'."""
    return "%s.tx_peer_eap_peap" % mon_if

def RX_PEER_PEAP_QUEUE(mon_if):
    """Return name of queue used for PEAP messages received for a peer on
    monitoring interface 'mon_if'."""
    return "%s.rx_peer_peap" % mon_if

def RX_PEER_EAP_TLS_QUEUE(mon_if):
    """Return name of queue used for EAP TLS messages received for a peer on
    monitoring interface 'mon_if'."""
    return "%s.rx_peer_eap_tls" % mon_if

def TX_PEER_EAP_TLS_QUEUE(mon_if):
    """Return name of queue used for EAP TLS messages to be send as a peer on
    monitoring interface 'mon_if'."""
    return "%s.tx_peer_eap_tls" % mon_if

def RX_PEER_TLS_QUEUE(mon_if):
    """Return name of queue used for TLS messages received for a peer on
    monitoring interface 'mon_if'."""
    return "%s.rx_peer_tls" % mon_if

def RX_AUTH_EAP_QUEUE(mon_if):
    """Return name of queue used for EAP messages received for an authenticator
    on monitoring interface 'mon_if'."""
    return "%s.rx_auth_eap" % mon_if

def TX_AUTH_EAP_QUEUE(mon_if):
    """Return name of queue used for EAP messages to be send as an authenticator
    on monitoring interface 'mon_if'."""
    return "%s.tx_auth_eap" % mon_if

def rx_eap(r, mon_if, sta_list = None):
    """EAP layer / RX"""

    for f in frames_in_scope(r, RX_EAP_FRAME_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3
        eap = f[EAP]
        msg = {'sta' : sta, 'bssid' : bssid, 'eap' : str(eap)}

        seen_eap_id = r.hget('eap_id', (sta, bssid))
        if str(eap.id) == seen_eap_id:
            logger.debug("detected EAP duplicate with EAP.ID '%s'", eap.id, \
                    extra = {'sta' : sta, 'bssid' : bssid})
            continue
        else:
            r.hset('eap_id', (sta, bssid), eap.id)

        if eap.code == EAP.REQUEST:
            if eap.type == EAP.TYPE_ID:
                r.publish(RX_PEER_EAP_ID_QUEUE(mon_if), msg)
            elif eap.type == EAP.TYPE_PEAP:
                r.publish(RX_PEER_EAP_PEAP_QUEUE(mon_if), msg)
            elif eap.type == EAP.TYPE_TLS:
                r.publish(RX_PEER_EAP_TLS_QUEUE(mon_if), msg)
            else:
                logger.warning("received EAP peer message with unsupported type '%s'", eap.type, \
                        extra = {'sta' : sta, 'bssid' : bssid})
        elif eap.code == EAP.SUCCESS:
            print "[+] EAP success"
        elif eap.code == EAP.FAILURE:
            print "[-] EAP failure"
        elif eap.code == EAP.RESPONSE:
            r.publish(RX_AUTH_EAP_QUEUE(mon_if), msg)
        else:
            logger.warning("received EAP message with illegal code '%s'", eap.code, \
                    extra = {'sta' : sta, 'bssid' : bssid})

def get_eap_frag(r, sta, bssid):
    f = r.hget('eap_frag', (sta, bssid))
    return f if f else ""

def set_eap_frag(r, sta, bssid, frag):
    r.hset('eap_frag', (sta, bssid), frag)

def peer_eap_tx(r, mon_if, sta_list = None):
    """EAP peer layer / TX"""

    ps = r.pubsub()
    ps.subscribe(TX_PEER_EAP_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        (state, sn) = get_state(r, sta, bssid)

        eap = EAP(msg['eap'])

        mgt = Dot11(subtype = Dot11.SUBTYPE['Data']['Data'],\
                type = Dot11.TYPE_DATA,\
                FCfield = "to-DS",
                addr1 = bssid,
                addr2 = sta,
                addr3 = bssid,
                SC = sn << 4)
        f = mgt/LLC()/SNAP()/EAPOL()/eap

        # TODO implement retransmission

        set_state(r, sta, bssid, state, sn + 1)

        r.publish(TX_FRAME_QUEUE(mon_if), f)

def peer_eap_id(r, mon_if, sta_list = None, \
        eapid = EAP(code = EAP.RESPONSE, type = EAP.TYPE_ID)/"user@domain.com"):
    """Return EAP ID on request"""

    ps = r.pubsub()
    ps.subscribe(RX_PEER_EAP_ID_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eap = EAP(msg['eap'])

        eapid.id = eap.id

        logger.debug("answering EAP ID request", \
                extra = {'sta' : sta, 'bssid' : bssid})

        r.publish(TX_PEER_EAP_QUEUE(mon_if), {\
                'sta'    : sta,
                'bssid'  : bssid,
                'eap'    : str(eapid)})

def peer_eap_peap_rx(r, mon_if, sta_list = None):
    """EAP-PEAP peer layer / RX"""

    ps = r.pubsub()
    ps.subscribe(RX_PEER_EAP_PEAP_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eap = EAP(msg['eap'])
        eapTls = eap[EAPTLSRequest]

        if eapTls.EAP_TLS_start == 1:
            if eapTls.length_included == 1 and eapTls.tls_msg_len != 0:
                logger.warning("received EAP-PEAP/Start with non-zero length", \
                        extra = {'sta' : sta, 'bssid' : bssid})
                continue
            elif eapTls.more_fragments != 0:
                logger.warning("received EAP-PEAP/Start with fragments", \
                        extra = {'sta' : sta, 'bssid' : bssid})
                continue
            else:
                r.publish(RX_PEER_PEAP_QUEUE(mon_if), {\
                        'sta'       : sta,
                        'bssid'     : bssid,
                        'eap-id'    : str(eap.id),
                        'tls-start' : str(eapTls.EAP_TLS_start),
                        'tls'       : ''
                        })

        elif eapTls.more_fragments == 1:
            frag = get_eap_frag(r, sta, bssid) + str(eapTls.payload)
            set_eap_frag(r, sta, bssid, frag)

            if len(frag) >= eapTls.tls_msg_len:
                logger.warning("expecting more frags exceeding EAP-PEAP msg len", \
                    extra = {'sta' : sta, 'bssid' : bssid})

            # ack fragment
            r.publish(TX_PEER_EAP_PEAP_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap-id'     : str(eap.id),
                    'tls-record' : ''
                    })

        else: # eapTls.more_fragments == 0:
            frag = get_eap_frag(r, sta, bssid) + str(eapTls.payload)
            set_eap_frag(r, sta, bssid, "")

            # publish defragmented PEAP msg
            r.publish(RX_PEER_PEAP_QUEUE(mon_if), {\
                    'sta'       : sta,
                    'bssid'     : bssid,
                    'eap-id'    : str(eap.id),
                    'tls-start' : str(eapTls.EAP_TLS_start),
                    'tls'       : frag
                    })

def peer_eap_peap_tx(r, mon_if, sta_list = None):
    """EAP-PEAP peer layer / TX"""

    ps = r.pubsub()
    ps.subscribe(TX_PEER_EAP_PEAP_QUEUE(mon_if))

    # TODO implement fragmentation
    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eapId = int(msg['eap-id'])
        tlsRec = msg['tls-record']

        if len(tlsRec) > 0:
            eap = EAP(code = EAP.RESPONSE, id = eapId, type = EAP.TYPE_PEAP)/EAPTLSResponse()/tlsRec
        else:
            eap = EAP(code = EAP.RESPONSE, id = eapId, type = EAP.TYPE_PEAP)/EAPTLSResponse()

        r.publish(TX_PEER_EAP_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap'        : str(eap),
                    })

def peer_peap_rx(r, mon_if, sta_list = None, \
        client_hello = TLSClientHello(compression_methods=range(0xff), cipher_suites=range(0xff))):
    """PEAP peer layer / RX"""

    ps = r.pubsub()
    ps.subscribe(RX_PEER_TLS_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eapId = msg['eap-id']
        tlsStart = int(msg['tls-start'])
        tls = SSL(msg['tls'])

        if tlsStart:
            logger.debug("received EAP-PEAP/Start", \
                    extra = {'sta' : sta, 'bssid' : bssid})
            logger.debug("sending EAP-TLS Client Hello", \
                    extra = {'sta' : sta, 'bssid' : bssid})

            tlsRec = TLSRecord()/TLSHandshake()/client_hello
            r.publish(TX_PEER_EAP_PEAP_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap-id'     : eapId,
                    'tls-record' : str(tlsRec)
                    })
        else:
            tls.show2()

def peer_eap_tls_rx(r, mon_if, sta_list = None):
    """EAP-TLS peer layer / RX"""

    ps = r.pubsub()
    ps.subscribe(RX_PEER_EAP_TLS_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eap = EAP(msg['eap'])
        eapTls = eap[EAPTLSRequest]

        if eapTls.EAP_TLS_start == 1:
            if eapTls.length_included == 1 and eapTls.tls_msg_len != 0:
                logger.warning("received EAP-TLS/Start with non-zero length", \
                        extra = {'sta' : sta, 'bssid' : bssid})
                continue
            elif eapTls.more_fragments != 0:
                logger.warning("received EAP-TLS/Start with fragments", \
                        extra = {'sta' : sta, 'bssid' : bssid})
                continue
            else:
                r.publish(RX_PEER_TLS_QUEUE(mon_if), {\
                        'sta'       : sta,
                        'bssid'     : bssid,
                        'eap-id'    : str(eap.id),
                        'tls-start' : str(eapTls.EAP_TLS_start),
                        'tls'       : ''
                        })

        elif eapTls.more_fragments == 1:
            frag = get_eap_frag(r, sta, bssid) + str(eapTls.payload)
            set_eap_frag(r, sta, bssid, frag)

            if len(frag) >= eapTls.tls_msg_len:
                logger.warning("expecting more frags exceeding EAP-TLS msg len", \
                    extra = {'sta' : sta, 'bssid' : bssid})

            # ack fragment
            r.publish(TX_PEER_EAP_TLS_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap-id'     : str(eap.id),
                    'tls-record' : ''
                    })

def peer_eap_tls_tx(r, mon_if, sta_list = None):
    """EAP-TLS peer layer / TX"""

    ps = r.pubsub()
    ps.subscribe(TX_PEER_EAP_TLS_QUEUE(mon_if))

    # TODO implement fragmentation
    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eapId = int(msg['eap-id'])
        tlsRec = msg['tls-record']

        if len(tlsRec) > 0:
            eap = EAP(code = EAP.RESPONSE, id = eapId, type = EAP.TYPE_TLS)/EAPTLSResponse()/tlsRec
        else:
            eap = EAP(code = EAP.RESPONSE, id = eapId, type = EAP.TYPE_TLS)/EAPTLSResponse()

        r.publish(TX_PEER_EAP_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap'        : str(eap),
                    })

def peer_tls_rx(r, mon_if, sta_list = None, \
        client_hello = TLSClientHello(compression_methods=range(0xff), cipher_suites=range(0xff))):
    """TLS peer layer / RX"""

    ps = r.pubsub()
    ps.subscribe(RX_PEER_TLS_QUEUE(mon_if))

    for m in ps.listen():
        if m['type'] != 'message':
            continue
        msg = ast.literal_eval(m['data'])
        sta = msg['sta']

        # skip frame if STA is not in scope
        if sta_list and sta not in sta_list:
            continue

        bssid = msg['bssid']
        eapId = msg['eap-id']
        tlsStart = int(msg['tls-start'])
        tls = SSL(msg['tls'])

        if tlsStart:
            logger.debug("received EAP-TLS/Start", \
                    extra = {'sta' : sta, 'bssid' : bssid})
            logger.debug("sending EAP-TLS Client Hello", \
                    extra = {'sta' : sta, 'bssid' : bssid})

            tlsRec = TLSRecord()/TLSHandshake()/client_hello
            r.publish(TX_PEER_EAP_TLS_QUEUE(mon_if), {\
                    'sta'        : sta,
                    'bssid'      : bssid,
                    'eap-id'     : eapId,
                    'tls-record' : str(tlsRec)
                    })

