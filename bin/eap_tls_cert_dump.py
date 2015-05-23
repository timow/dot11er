#!/usr/bin/python

import sys
import redis

from dot11er.state_machine import *
from dot11er.util import start_process, default_arg_parser, redis_obj

RSN_INFO = Dot11Elt(ID = DOT11_INFO_ELT['RSN'], \
        info = Dot11RSNElt(
            PCS_List = [Dot11CipherSuite(Suite_Type = DOT11_CIPHER_SUITE_TYPE['CCMP'])],
            AKM_List = [Dot11AKMSuite(Suite_Type = DOT11_AKM_SUITE_SELECTOR['IEEE802.1X'])]))

def eap_tls_server_cert_dump(r, mon_if, sta_list = None):
    for f in frames_in_scope(r, RX_EAP_QUEUE(mon_if), sta_list):
        sta = f.addr1
        bssid = f.addr3

        if r.hget('state', sm(sta,bssid)) == 'eap_tls_client_hello':
            eap = f[EAP]
            if eap.code != EAP.REQUEST or eap.type != EAP.TYPE_TLS \
                    or not eap.haslayer(SSL):
                continue

            # TODO introduce proper logging
            print "[+] EAP TLS Server Cert Dump (BSSID '%s')" % (bssid)

            ssl = eap[SSL]
            for r in ssl.records:
                if r.content_type == 0x16: # handshake
                    h = r[TLSHandshake]
                    if h.type == 0x0b: # certificate
                        certList = h[TLSCertificateList]
                        cert = certList.certificates[0]
                        c = open("{bssid}.der".format(bssid = bssid), 'wb')
                        c.write(cert.data)
                        c.close()
                        return


if __name__ == '__main__':
    parser = default_arg_parser()
    parser.description = 'EAP-TLS Server Cert Dump.'
    parser.add_argument('-s', '--sta_id', default = str(RandMAC()), \
            help = 'STA ID to be used for connecting (default: random MAC)')
    parser.add_argument('essid', \
            help = 'ESSID for which the cert shall be dumped')
    parser.add_argument('bssid', \
            help = 'BSSID for which the cert shall be dumped')
    args = parser.parse_args()

    mon_if = args.mon_if
    sta_ids = [args.sta_id]

    # start all transition handlers
    p_auth = start_process(authentication, (redis_obj(args), mon_if, sta_ids))
    p_assoc = start_process(association, (redis_obj(args), mon_if, sta_ids), \
            {'rsn_info' : RSN_INFO})
    p_eapol_start = start_process(eapol_start, (redis_obj(args), mon_if, sta_ids))
    p_eap_id = start_process(eap_id, (redis_obj(args), mon_if, sta_ids))
    p_eap_tls_client_hello = start_process(eap_tls_client_hello, \
        (redis_obj(args), mon_if, sta_ids))
    p_cert_dump = start_process(eap_tls_server_cert_dump, \
        (redis_obj(args), mon_if, sta_ids))

    # initiate dump via probe request
    r = redis_obj(args)
    r.publish(TX_PROBE_QUEUE(mon_if), {\
            'sta'   : args.sta_id,
            'bssid' : args.bssid,
            'essid' : args.essid,
            })

    # wait for successful dump
    p_cert_dump.join()

    # terminate other state transition handlers
    p_auth.terminate()
    p_assoc.terminate()
    p_eapol_start.terminate()
    p_eap_id.terminate()
    p_eap_tls_client_hello.terminate()
