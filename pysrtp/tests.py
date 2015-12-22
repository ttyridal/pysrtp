import unittest
from binascii import unhexlify
import collections
import itertools
import struct

from . import aes128_cm as aes_cm
from . import aes128_gcm as aes_gcm
from . import srtp as pysrtp
from . import utils
from . import errors


class srtp_tests(unittest.TestCase):
    unprotected_rtcp = unhexlify((
        '81 c8 00 05 de ad be ef  00 00 00 00 00 00 00 00'
        '00 00 00 00 00 00 00 00  00 00 00 00').replace(' ', ''))
    unprotected_rtp = unhexlify((
        '80 40 f1 7b 80 41 f8 d3  55 01 a0 b2 47 61 6c 6c'
        '69 61 20 65 73 74 20 6f  6d 6e 69 73 20 64 69 76'
        '69 73 61 20 69 6e 20 70  61 72 74 65 73 20 74 72'
        '65 73').replace(' ', ''))
    libsrtp_gcm_protected_rtcp = unhexlify((
        '81 c8 00 05 de ad be ef  1f d6 ff 53 aa 58 17 ea '
        '0b ce e1 28 14 ad 0a c7  cc 2c 9e 75 10 7c 6c a2 '
        '2b 64 f0 4e ec 0c 98 f1  12 34 44 d1 80 00 00 01'
        ).replace(' ', ''))
    gcm_protected_rtp = unhexlify((
        '80 40 f1 7b 80 41 f8 d3  55 01 a0 b2 11 74 39 45'
        'e8 0b 2e 35 a6 e2 60 08  c2 48 95 1f 36 ea fc 8d'
        '89 a9 29 fc 54 c9 ba b4  f8 95 95 7c 41 23 e9 4a'
        '65 8c e8 32 d7 6d 50 97  5f d2 c9 93 5d 13 eb b3'
        'ec 4f').replace(' ', ''))
    cm_protected_rtp = unhexlify((
        '80 40 f1 7b 80 41 f8 d3  55 01 a0 b2 f8 29 00 a9'
        '98 93 e1 a9 18 a9 ba 8c  c1 24 18 74 cb 64 8b 7b'
        'ed b5 94 fb 76 35 a1 5d  10 03 20 ea 03 d4 0e 1b'
        '17 74 7f 45 49 bc 57 22  72 c5 54 13').replace(' ', ''))
    cm_protected_rtcp = unhexlify((
        '81 c8 00 05 de ad be ef  bc dd b2 a1 80 7f 8e e7'
        'a8 90 d5 03 ef 23 d9 1b  0b de ae 8a 80 00 00 01'
        '32 9c 05 e0 a1 30 30 7f 0b 1e').replace(' ', ''))

    def test_gcm_unencrypted_rtcp(self):
        srtp = pysrtp.SRTP(
            'AEAD_AES_128_GCM',
            b'\0'*16, b'\0'*14,
            ['UNENCRYPTED_SRTCP'])

        x = srtp.protectRtcp(self.unprotected_rtcp)
        self.assertEqual(x[:-20], self.unprotected_rtcp)
        self.assertEqual(x[-20:], unhexlify(
            '3959f1a052f2473e2021574f8eff24ce00000001'))
        dta = srtp.unprotectRtcp(x)
        self.assertEqual(dta, self.unprotected_rtcp)

    def test_cm_unencrypted_rtcp(self):
        srtp = pysrtp.SRTP(
            'AES_CM_128_HMAC_SHA1_80',
            b'\0'*16, b'\0'*14,
            ['UNENCRYPTED_SRTCP'])

        x = srtp.protectRtcp(self.unprotected_rtcp)
        self.assertEqual(x[:-14], self.unprotected_rtcp)
        self.assertEqual(x[-14:], unhexlify(
            '00000001f01934604dcd61e0115b'))
        dta = srtp.unprotectRtcp(x)
        self.assertEqual(dta, self.unprotected_rtcp)

    def test_aes_gcm_protect(self):
        srtp = pysrtp.SRTP('AEAD_AES_128_GCM', b'\0'*16, b'\0'*14)

        x = srtp.protectRtp(self.unprotected_rtp)
        self.assertEqual(x, self.gcm_protected_rtp)

        x = srtp.protectRtcp(self.unprotected_rtcp)
        self.assertEqual(x, self.libsrtp_gcm_protected_rtcp)

    def test_aes_gcm_unprotect(self):
        srtp = pysrtp.SRTP('AEAD_AES_128_GCM', b'\0'*16, b'\0'*14)

        tampered = bytearray(self.libsrtp_gcm_protected_rtcp)
        tampered[4] += 1
        with self.assertRaises(errors.AuthenticationFailure):
            srtp.unprotectRtcp(tampered)

        res = srtp.unprotectRtcp(self.libsrtp_gcm_protected_rtcp)
        self.assertEqual(res, self.unprotected_rtcp)

        tampered = bytearray(self.gcm_protected_rtp)
        tampered[4] += 1
        with self.assertRaises(errors.AuthenticationFailure):
            srtp.unprotectRtp(tampered)

        res = srtp.unprotectRtp(self.gcm_protected_rtp)
        self.assertEqual(res, self.unprotected_rtp)

    def test_aes_cm_sha_protect(self):
        srtp = pysrtp.SRTP('AES_CM_128_HMAC_SHA1_80', b'\0'*16, b'\0'*14)

        x = srtp.protectRtp(self.unprotected_rtp)
        self.assertEqual(x, self.cm_protected_rtp)

        x = srtp.protectRtcp(self.unprotected_rtcp)
        self.assertEqual(x, self.cm_protected_rtcp)

    def test_aes_cm_sha32_protect(self):
        srtp = pysrtp.SRTP('AES_CM_128_HMAC_SHA1_32', b'\0'*16, b'\0'*14)

        x = srtp.protectRtp(self.unprotected_rtp)
        self.assertEqual(x, self.cm_protected_rtp[:-6])

        x = srtp.protectRtcp(self.unprotected_rtcp)
        self.assertEqual(x, self.cm_protected_rtcp[:-6])

    def test_aes_cm_sha_unprotect(self):
        srtp = pysrtp.SRTP('AES_CM_128_HMAC_SHA1_80', b'\0'*16, b'\0'*14)

        tampered = bytearray(self.cm_protected_rtp)
        tampered[4] += 1

        with self.assertRaises(errors.AuthenticationFailure):
            srtp.unprotectRtp(tampered)

        dta = srtp.unprotectRtp(self.cm_protected_rtp)
        self.assertEqual(dta, self.unprotected_rtp)

        tampered = bytearray(self.cm_protected_rtcp[:])
        tampered[4] += 1
        with self.assertRaises(errors.AuthenticationFailure):
            srtp.unprotectRtcp(tampered)

        dta = srtp.unprotectRtcp(self.cm_protected_rtcp)
        self.assertEqual(dta, self.unprotected_rtcp)

    def test_aes_cm_sha32_unprotect(self):
        srtp = pysrtp.SRTP('AES_CM_128_HMAC_SHA1_32', b'\0'*16, b'\0'*14)

        dta = srtp.unprotectRtp(self.cm_protected_rtp[:-6])
        self.assertEqual(dta, self.unprotected_rtp)

        dta = srtp.unprotectRtcp(self.cm_protected_rtcp[:-6])
        self.assertEqual(dta, self.unprotected_rtcp)

    def test_reject_unknown_alg(self):
        with self.assertRaises(errors.UnimplementedAlgorithm):
            pysrtp.SRTP('F8_HMAC_SHA1_32', b'\0'*16, b'\0'*14)


class aes_gcm_tests(unittest.TestCase):

    def test_libsrtp_bug(self):
        data = unhexlify((
            '81 c8 00 05 de ad be ef  00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00  00 00 00 00').replace(' ', ''))

        libsrtp_protected = unhexlify((
            '81 c8 00 05 de ad be ef  1f d6 ff 53 aa 58 17 ea'
            '0b ce e1 28 14 ad 0a c7  cc 2c 9e 75 10 7c 6c a2'
            '2b 64 f0 4e ec 0c 98 f1  12 34 44 d1 80 00 00 01'
        ).replace(' ', ''))

        salt = unhexlify('0000000000000000000000000000')
        key = unhexlify('00000000000000000000000000000000')
        ssrc = utils.rtcp_ssrc(data)
        pkt_i = 1

        keys = aes_gcm.derive_keys(key, salt).rtcp

        # !!! libSRTP seems to f.. this up.
        aad = data[:8] + struct.pack("<L", pkt_i + (1 << 31))
        dta, tag = aes_gcm.encrypt(keys, ssrc, pkt_i, data[8:], aad)
        dta = data[:8] + dta + tag + struct.pack(">L", pkt_i + (1 << 31))

        self.assertEqual(libsrtp_protected, dta)

    def test_srtcp_decrypt(self):
        data = unhexlify(('81c8000d4d61727363e94885dcdab67ca727d7662f6b7e'
                          '997ff5c0f76c06f32dc676a5f1730d6fda4ce09b468630'
                          '3ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade'
                          '800005d4'))
        expected = unhexlify((
            '4e 54 50 31 4e 54 50 32  52 54 50 20 00 00 04 2a'
            '00 00 e9 30 4c 75 6e 61  de ad be ef de ad be ef'
            'de ad be ef de ad be ef de ad be ef').replace(' ', ''))
        salt = unhexlify('517569642070726f2071756f')
        key = unhexlify('000102030405060708090a0b0c0d0e0f')
        ssrc = utils.rtcp_ssrc(data)
        pkt_i = utils.parse_esrtcp_word(data[-4:]).index

        keys = collections.namedtuple('Keys', 'key, salt, table')(
            key, salt, aes_gcm._genereate_auth_table(key))

        cipher = data[8:-20]
        tag = data[-20:-4]
        aad = data[:8] + data[-4:]

        dta, _ = aes_gcm.decrypt(keys, ssrc, pkt_i, cipher, tag, aad)
        self.assertEqual(dta, expected)

    def test_rtp_rfc_vectors(self):
        pkt = unhexlify(('8040f17b8041f8d35501a0b247616c6c69612065'
                         '7374206f6d6e69732064697669736120696e2070'
                         '61727465732074726573'))
        salt = unhexlify('517569642070726f2071756f')
        key = unhexlify('000102030405060708090a0b0c0d0e0f')

        roc = 0

        rtph = utils.parse_rtp_header(pkt)
        ssrc, seq, hlen = rtph.ssrc, rtph.seq, rtph.hlen
        pkt_i = utils.packet_index(roc, seq)

        iv = aes_gcm._calc_iv(salt, ssrc, pkt_i)
        self.assertEqual(iv, unhexlify('51753c6580c2726f20718414'))

        keys = collections.namedtuple('Keys', 'key, salt, table')(
            key, salt, aes_gcm._genereate_auth_table(key))

        cipher, tag = aes_gcm.encrypt(
            keys,
            ssrc,
            pkt_i,
            pkt[hlen:],
            pkt[:hlen])

        expected_cipher = unhexlify(('f24de3a3fb34de6cacba861c9d7e4b'
                                     'cabe633bd50d294e6f42a5f47a51c7'
                                     'd19b36de3adf8833'))
        expected_tag = unhexlify('899d7f27beb16a9152cf765ee4390cce')
        self.assertEqual(cipher, expected_cipher)
        self.assertEqual(tag, expected_tag)

        dta, tag = aes_gcm.decrypt(keys, ssrc, pkt_i, cipher, tag, pkt[:hlen])
        self.assertEqual(dta, pkt[hlen:])

        with self.assertRaises(errors.AuthenticationFailure):
            aes_gcm.decrypt(keys, ssrc, pkt_i, cipher, tag+b"b", pkt[:hlen])


class aes_cm_tests(unittest.TestCase):

    def test_derive_keys(self):
        #test srtp_derive_key_aes_128
        master_key = unhexlify('E1F97A0D3E018BE0D64FA32C06DE4139')
        master_salt = unhexlify('0EC675AD498AFEEBB6960B3AABE6')
        keys = aes_cm.derive_keys(master_key, master_salt)
        self.assertEqual(
            keys.rtp.key,
            unhexlify('C61E7A93744F39EE10734AFE3FF7A087'))
        self.assertEqual(
            keys.rtp.salt,
            unhexlify('30CBBC08863D8C85D49DB34A9AE1'))
        self.assertEqual(
            keys.rtp.auth,
            unhexlify('CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4'))

    def test_srtp_aes_ctr_vectors(self):
        LOTS_OF_ZEROS = b'\0' * 16 * 2**16
        session_key = unhexlify('2B7E151628AED2A6ABF7158809CF4F3C')
        session_salt = unhexlify('F0F1F2F3F4F5F6F7F8F9FAFBFCFD')
        keys = collections.namedtuple('Keys', 'key, salt, auth')(
            session_key, session_salt, None)
        ssrc = 0
        pkt_i = 0
        result = aes_cm.encrypt(keys, pkt_i, ssrc, LOTS_OF_ZEROS)
        self.assertEqual(
            result[0x0000*16:0x0001*16],
            unhexlify('E03EAD0935C95E80E166B16DD92B4EB4'))
        self.assertEqual(
            result[0x0001*16:0x0002*16],
            unhexlify('D23513162B02D0F72A43A2FE4A5F97AB'))
        self.assertEqual(
            result[0x0002*16:0x0003*16],
            unhexlify('41E95B3BB0A2E8DD477901E4FCA894C0'))
        self.assertEqual(
            result[0xfeff*16:0xff00*16],
            unhexlify('EC8CDF7398607CB0F2D21675EA9EA1E4'))
        self.assertEqual(
            result[0xff00*16:0xff01*16],
            unhexlify('362B7C3C6773516318A077D7FC5073AE'))
        self.assertEqual(
            result[0xff01*16:0xff02*16],
            unhexlify('6A2CC3787889374FBEB4C81B17BA6C44'))

    def test_srtp_packet_index_respected(self):
        session_key = unhexlify('66e94bd4ef8a2c3b884cfa59ca342b2e')
        session_salt = unhexlify('b5b03421de8bbffc4eadec767339')
        pkt_i = itertools.count(1)
        data = b'hello\n\0'
        ssrc = 0xdeadbeef
        keys = collections.namedtuple('Keys', 'key, salt, auth')(
            session_key, session_salt, None)

        result = aes_cm.encrypt(keys, next(pkt_i), ssrc, data)
        self.assertEqual(result, unhexlify('3274f91afdc83f'))

        result = aes_cm.encrypt(keys, next(pkt_i), ssrc, data)
        self.assertEqual(result, unhexlify('48cac42ee1864f'))

        result = aes_cm.encrypt(keys, next(pkt_i), ssrc, data)
        self.assertEqual(result, unhexlify('29a643c72a26a5'))
