"""SRTP AES-GCM
Heavily inspired by https://github.com/bozhu/AES-GCM-Python
"""
import collections
from Crypto.Cipher import AES
from Crypto.Util import Counter
from .utils import bytes_to_int, int_to_bytes
from .errors import AuthenticationFailure
from . import aes128_cm


def derive_keys(master_key, master_salt, packet_i=0, key_derivation_rate=0):
    keys = aes128_cm.derive_keys(master_key,
                                 master_salt,
                                 packet_i,
                                 key_derivation_rate)

    _SRTP_session_keys_ = collections.namedtuple(
        'SRTP_session_keys_', 'key, salt, table')
    _SRTP_session_keys = collections.namedtuple(
        'SRTP_session_keys', 'rtp, rtcp')

    rtpt = _genereate_auth_table(keys.rtp.key)
    rtcpt = _genereate_auth_table(keys.rtcp.key)

    return _SRTP_session_keys(
        _SRTP_session_keys_(keys.rtp.key, keys.rtp.salt[:12], rtpt),
        _SRTP_session_keys_(keys.rtcp.key, keys.rtcp.salt[:12], rtcpt))


def _calc_iv(salt, ssrc, pkt_i):
    salt = bytes_to_int(salt)
    iv = ((ssrc << (48)) + pkt_i) ^ salt
    return int_to_bytes(iv, 12)


def __gf_2_128_mul(x, y):
    """from https://github.com/bozhu/AES-GCM-Python
        GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
        Please note the MSB is x0 and LSB is x127"""
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res


def __gen_H_table(authkey):
    """from https://github.com/bozhu/AES-GCM-Python"""
    table = []  # for 8-bit
    for i in range(16):
        row = []
        for j in range(256):
            row.append(__gf_2_128_mul(authkey, j << (8 * i)))
        table.append(tuple(row))
    return table


def __times_auth_table(table, val):
    """from https://github.com/bozhu/AES-GCM-Python"""
    res = 0
    for i in range(16):
        res ^= table[i][val & 0xFF]
        val >>= 8
    return res


def _genereate_auth_table(key):
    H = AES.new(key, AES.MODE_ECB).encrypt(b'\0' * 16)
    table = __gen_H_table(bytes_to_int(H))
    return table


def gmac(table, first_block, data, aad=None):
    partial_hash = 0

    for aad_block in [aad[i:i+16] for i in range(0, len(aad), 16)]:
        block_int = bytes_to_int(aad_block) << 8 * (16 - len(aad_block))
        partial_hash = __times_auth_table(table, block_int ^ partial_hash)

    for data_block in [memoryview(data)[i:i+16] for i in
                       range(0, 16*(len(data)//16), 16)]:
        block_int = bytes_to_int(data_block)
        partial_hash = __times_auth_table(table, block_int ^ partial_hash)
    if len(data) % 16:
        data_block = data[16*(len(data)//16):]
        block_int = bytes_to_int(data_block) << 8 * (16 - len(data_block))
        partial_hash = __times_auth_table(table, block_int ^ partial_hash)

    lword = (8 * len(aad) << 64) + len(data) * 8
    partial_hash = __times_auth_table(table, lword ^ partial_hash)
    tag = int_to_bytes(bytes_to_int(first_block) ^ partial_hash, 16)

    return tag


def encrypt(keys, ssrc, pkt_i, data, aad=None):
    iv = _calc_iv(keys.salt, ssrc, pkt_i)

    counter = Counter.new(nbits=32, prefix=iv)
    keystream = AES.new(keys.key, AES.MODE_CTR, counter=counter)
    first_block = keystream.encrypt(b'\0'*16)

    cipher = keystream.encrypt(data)
    tag = gmac(keys.table, first_block, cipher, aad)
    return cipher, tag


def decrypt(keys, ssrc, pkt_i, cipher, tag, aad=None):
    iv = _calc_iv(keys.salt, ssrc, pkt_i)

    counter = Counter.new(nbits=32, prefix=iv)
    keystream = AES.new(keys.key, AES.MODE_CTR, counter=counter)
    first_block = keystream.encrypt(b'\0'*16)

    rtag = gmac(keys.table, first_block, cipher, aad)
    if tag and tag != rtag:
        raise AuthenticationFailure()
    return keystream.decrypt(cipher), rtag
