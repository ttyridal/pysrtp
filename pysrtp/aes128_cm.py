""""https://tools.ietf.org/html/rfc3711#section-4.3.1 - SRTP AES-SHA
Heavily inspired by https://github.com/goncalopp/srtp_decryption
"""

import Crypto.Cipher.AES as AES
import Crypto.Util.Counter as AESCounter
from Crypto.Hash.HMAC import HMAC
import Crypto.Hash.SHA
from .utils import bytes_to_int
import collections


def derive_keys(master_key, master_salt, pkt_i=0, key_derivation_rate=0):
    '''SRTP key derivation, https://tools.ietf.org/html/rfc3711#section-4.3'''
    _SRTP_session_keys_ = collections.namedtuple(
        'SRTP_session_keys_', 'key, salt, auth')
    _SRTP_session_keys = collections.namedtuple(
        'SRTP_session_keys', 'rtp, rtcp')

    assert len(master_key) == 128 // 8
    assert len(master_salt) == 112 // 8
    salt = bytes_to_int(master_salt)

    DIV = lambda x, y: 0 if y == 0 else x // y
    prng = lambda iv: AES.new(
        key=master_key,
        mode=AES.MODE_CTR,
        counter=AESCounter.new(nbits=128, initial_value=iv)
        ).encrypt(b'\0'*32)
    r = DIV(pkt_i, key_derivation_rate)  # pkt_i is always 48 bits
    derive_key_from_label = lambda label: prng(
        (salt ^ ((label << 48) + r)) << 16)

    rtp_keys = _SRTP_session_keys_(
        derive_key_from_label(0)[:16],
        derive_key_from_label(2)[:14],
        derive_key_from_label(1)[:20])

    rtcp_keys = _SRTP_session_keys_(
        derive_key_from_label(3)[:16],
        derive_key_from_label(5)[:14],
        derive_key_from_label(4)[:20])

    return _SRTP_session_keys(rtp_keys, rtcp_keys)


def _calc_iv(salt, ssrc, pkt_i):
    salt = bytes_to_int(salt)
    return ((ssrc << 64) + (pkt_i << 16)) ^ (salt << 16)


def encrypt(keys, packet_index, ssrc, data):
    '''En/decrypts SRTP data using AES counter keystream.
    https://tools.ietf.org/html/rfc3711#section-4.1.1'''
    iv = _calc_iv(keys.salt, ssrc, packet_index)

    counter = AESCounter.new(nbits=128, initial_value=iv)
    aes = AES.new(key=keys.key, mode=AES.MODE_CTR, counter=counter)

    return aes.encrypt(data)

decrypt = encrypt


def compute_hash(key, pkt, pre=None, post=None):
    if (pre):
        h = HMAC(key, pre, Crypto.Hash.SHA)
        h.update(pkt)
    else:
        h = HMAC(key, pkt, Crypto.Hash.SHA)
    if post:
        h.update(post)
    return h.digest()
