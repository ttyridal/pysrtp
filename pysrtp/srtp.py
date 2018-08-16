from . import aes128_cm
from . import aes128_gcm
from .errors import AuthenticationFailure, UnimplementedAlgorithm
from . import utils
import logging
import itertools
import struct

logger = logging.getLogger(__name__)


class SRTP(object):
    def __init__(self, alg, master_key, master_salt, flags={}, **kwargs):
        if alg == 'AEAD_AES_128_GCM':
            self.keys = aes128_gcm.derive_keys(master_key, master_salt)
            self.libsrtp_bug = False
            self.tag_len = 16
            self.protectRtcp = self._protectRtcp_aead
            self.unprotectRtcp = self._unprotectRtcp_aead
            self.protectRtp = self._protectRtp_aead
            self.unprotectRtp = self._unprotectRtp_aead
        elif alg in ['AES_CM_128_HMAC_SHA1_32', 'AES_CM_128_HMAC_SHA1_80']:
            self.keys = aes128_cm.derive_keys(master_key, master_salt)
            if alg == 'AES_CM_128_HMAC_SHA1_80':
                self.tag_len = 10
            else:
                self.tag_len = 4
            self.protectRtcp = self._protectRtcp_cm
            self.unprotectRtcp = self._unprotectRtcp_cm
            self.protectRtp = self._protectRtp_cm
            self.unprotectRtp = self._unprotectRtp_cm
        else:
            raise UnimplementedAlgorithm(alg)

        self.roc = 0
        self.seq = 0
        self.rtcp_index = itertools.count(1)
        self.flags = flags

    def _protectRtcp_aead(self, pkt, **kwargs):
        rtcp_header = pkt[:8]
        payload = pkt[len(rtcp_header):]
        ssrc = utils.rtcp_ssrc(pkt)
        pkt_i = next(self.rtcp_index)
        ESRTCP = pkt_i

        if 'UNENCRYPTED_SRTCP' not in self.flags:
            ESRTCP += 1 << 31

        if self.libsrtp_bug:
            srtcph = struct.pack('<L', ESRTCP)
        else:
            srtcph = struct.pack('>L', ESRTCP)

        ESRTCP = struct.pack('!L', ESRTCP)

        if 'UNENCRYPTED_SRTCP' in self.flags:
            _, tag = aes128_gcm.encrypt(
                self.keys.rtcp,
                ssrc,
                pkt_i,
                b'',
                pkt + srtcph)
            return b''.join((pkt, tag, ESRTCP))
        else:
            cipher, tag = aes128_gcm.encrypt(
                self.keys.rtcp,
                ssrc,
                pkt_i,
                payload,
                rtcp_header + srtcph)
            return b''.join((rtcp_header, cipher, tag, ESRTCP))

    def _protectRtcp_cm(self, pkt, **kwargs):
        rtcp_header = pkt[:8]
        payload = pkt[len(rtcp_header):]
        ssrc = utils.rtcp_ssrc(pkt)
        pkt_i = next(self.rtcp_index)
        ESRTCP = pkt_i

        if 'UNENCRYPTED_SRTCP' not in self.flags:
            ESRTCP += 1 << 31

        ESRTCP = struct.pack('!L', ESRTCP)

        if 'UNENCRYPTED_SRTCP' in self.flags:
            cipher = payload
        else:
            cipher = aes128_cm.encrypt(
                self.keys.rtcp,
                pkt_i,
                ssrc,
                payload)

        tag = aes128_cm.compute_hash(
            self.keys.rtcp.auth,
            cipher,
            rtcp_header,
            ESRTCP)[:self.tag_len]

        return b''.join((rtcp_header, cipher, ESRTCP, tag))

    def _protectRtp_aead(self, pkt, **kwargs):
        rtph = utils.parse_rtp_header(pkt)
        rtp_header = pkt[:rtph.hlen]
        payload = pkt[len(rtp_header):]
        if rtph.seq < self.seq:
            self.roc += 1
        self.seq = rtph.seq
        pkt_i = utils.packet_index(self.roc, rtph.seq)

        cipher, tag = aes128_gcm.encrypt(
            self.keys.rtp,
            rtph.ssrc,
            pkt_i,
            payload,
            rtp_header)

        return b''.join((rtp_header, cipher, tag))

    def _protectRtp_cm(self, pkt, **kwargs):
        rtph = utils.parse_rtp_header(pkt)
        rtp_header = pkt[:rtph.hlen]
        payload = pkt[len(rtp_header):]
        if rtph.seq < self.seq:
            self.roc += 1
        self.seq = rtph.seq
        pkt_i = utils.packet_index(self.roc, rtph.seq)

        cipher = aes128_cm.encrypt(
            self.keys.rtp,
            pkt_i,
            rtph.ssrc,
            payload)

        tag = aes128_cm.compute_hash(
            self.keys.rtp.auth,
            cipher,
            pre=rtp_header,
            post=struct.pack('!L', self.roc))[:self.tag_len]

        return b''.join((rtp_header, cipher, tag[:self.tag_len]))

    def _unprotectRtcp_aead(self, pkt, **kwargs):
        rtcp_header = pkt[:8]
        cipher = pkt[len(rtcp_header):-self.tag_len-4]
        tag = pkt[len(rtcp_header)+len(cipher):-4]

        ESRTCP = pkt[-4:]
        ssrc = utils.rtcp_ssrc(pkt)
        esrtcp = utils.parse_esrtcp_word(ESRTCP)

        if self.libsrtp_bug:
            ESRTCP = struct.pack("<L", struct.unpack(">L", ESRTCP)[0])

        if esrtcp.encrypted:
            if 'UNENCRYPTED_SRTCP' in self.flags:
                logger.info(("UNENCRYPTED in session params, "
                             "but rtcp packet is encrypted"))

            aad = rtcp_header + ESRTCP

            dta, _ = aes128_gcm.decrypt(
                self.keys.rtcp,
                ssrc,
                esrtcp.index,
                cipher,
                tag,
                aad)
            return b''.join((rtcp_header, dta))
        else:
            if 'UNENCRYPTED_SRTCP' not in self.flags:
                logger.info(("UNENCRYPTED not in session params, "
                             "but rtcp packet is not encrypted"))
            _, _ = aes128_gcm.decrypt(
                self.keys.rtcp,
                ssrc,
                esrtcp.index,
                '',
                tag,
                pkt[:-self.tag_len-4] + ESRTCP)
            return pkt[:-self.tag_len-4]

    def _unprotectRtcp_cm(self, pkt, **kwargs):
        rtcp_header = pkt[:8]
        ssrc = struct.unpack_from('!L', pkt, 4)[0]
        pkt_tag = pkt[-self.tag_len:]
        esrtcp = utils.parse_esrtcp_word(pkt[-self.tag_len-4:-self.tag_len])
        cipher = pkt[len(rtcp_header):-len(pkt_tag)-4]

        tag = aes128_cm.compute_hash(self.keys.rtcp.auth, pkt[:-self.tag_len])

        if tag[:self.tag_len] != pkt_tag:
            raise AuthenticationFailure()

        if esrtcp.encrypted:
            if 'UNENCRYPTED_SRTCP' in self.flags:
                logger.info(("UNENCRYPTED in session params, "
                             "but rtcp packet is encrypted"))
            dta = aes128_cm.decrypt(
                self.keys.rtcp,
                esrtcp.index,
                ssrc,
                cipher)
            return b''.join((rtcp_header, dta))
        else:
            if 'UNENCRYPTED_SRTCP' not in self.flags:
                logger.info(("UNENCRYPTED not in session params, "
                             "but rtcp packet is not encrypted"))
            return pkt[:-self.tag_len-4]

    def _unprotectRtp_aead(self, pkt, **kwargs):
        rtph = utils.parse_rtp_header(pkt)
        if rtph.seq < self.seq:
            self.roc += 1
        self.seq = rtph.seq
        pkt_i = utils.packet_index(self.roc, rtph.seq)

        tag = pkt[-16:]
        rtp_header = pkt[:rtph.hlen]
        cipher = pkt[rtph.hlen:-16]

        dta, tag = aes128_gcm.decrypt(
            self.keys.rtp,
            rtph.ssrc,
            pkt_i,
            cipher,
            tag,
            rtp_header)

        return b''.join((rtp_header, dta))

    def _unprotectRtp_cm(self, pkt, **kwargs):
        rtph = utils.parse_rtp_header(pkt)
        if rtph.seq < self.seq:
            self.roc += 1
        self.seq = rtph.seq
        pkt_i = utils.packet_index(self.roc, rtph.seq)

        rtp_header = pkt[:rtph.hlen]

        if 'UNAUTHENTICATED_SRTP' not in self.flags:
            pkt_tag = pkt[-self.tag_len:]
            pkt = pkt[:-self.tag_len]

            tag = aes128_cm.compute_hash(
                self.keys.rtp.auth,
                pkt,
                post=utils.int_to_bytes(self.roc, 4))
            if tag[:self.tag_len] != pkt_tag:
                raise AuthenticationFailure()

        if 'UNENCRYPTED_SRTP' in self.flags:
            return pkt[:-self.tag_len]

        cipher = pkt[rtph.hlen:]

        dta = aes128_cm.decrypt(
            self.keys.rtp,
            pkt_i,
            rtph.ssrc,
            cipher)

        return b''.join((rtp_header, dta))
